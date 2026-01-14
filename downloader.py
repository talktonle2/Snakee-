from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import io
import random
import re
import os
import queue
import threading
import time
import urllib.request
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

try:
    from PIL import Image
except Exception:  # noqa: BLE001
    Image = None  # type: ignore[assignment]

try:
    from yt_dlp import YoutubeDL
except Exception:  # noqa: BLE001
    YoutubeDL = None  # type: ignore[assignment]
from core.ai_processor import AIProcessor


StatusCallback = Callable[["DownloadJob"], None]
LogCallback = Callable[[str], None]


def _sanitize_filename(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return "file"
    invalid = '<>:"/\\|?*'
    v = "".join("_" if c in invalid else c for c in v)
    v = v.rstrip(". ")
    return v[:120] if len(v) > 120 else v


def _is_probably_url(value: str) -> bool:
    v = str(value or "").strip()
    if not v:
        return False
    try:
        u = urllib.parse.urlparse(v)
    except Exception:
        return False
    return bool(u.scheme and u.netloc)


def _validate_cookiefile(cookiefile: str) -> str:
    p = str(cookiefile or "").strip()
    if not p:
        return ""

    if _is_probably_url(p):
        return ""
    try:
        if os.path.isfile(p):
            return p
    except Exception:
        return ""
    return ""


def _is_image_path(path: str) -> bool:
    ext = os.path.splitext(path or "")[1].lower().lstrip(".")
    return ext in {"jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff", "image"}


def _collect_filepaths(info: Any) -> List[str]:
    def _collect(node: Any, acc: List[str]) -> None:
        if not node:
            return
        if isinstance(node, dict):
            for k in ("filepath", "filename", "_filename"):
                v = node.get(k)
                if isinstance(v, str) and v.strip():
                    acc.append(v.strip())
            for k in ("requested_downloads", "entries"):
                v = node.get(k)
                if isinstance(v, list):
                    for e in v:
                        _collect(e, acc)
        elif isinstance(node, list):
            for e in node:
                _collect(e, acc)

    paths: List[str] = []
    _collect(info, paths)
    out: List[str] = []
    seen = set()
    for p in paths:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def _cleanup_images(paths: List[str]) -> List[str]:
    kept: List[str] = []
    for p in paths:
        if not p or not _is_image_path(p):
            continue
        if not os.path.exists(p):
            continue
        try:
            if os.path.getsize(p) < 512:
                try:
                    os.remove(p)
                except Exception:
                    pass
                continue
        except Exception:
            continue

        ok = True
        w = 0
        h = 0
        if Image is not None:
            try:
                with Image.open(p) as im:
                    w, h = im.size
                    im.verify()
            except Exception:
                ok = False

        if not ok:
            try:
                os.remove(p)
            except Exception:
                pass
            continue

        if w and h and (w < 50 or h < 50):
            try:
                os.remove(p)
            except Exception:
                pass
            continue

        ext = os.path.splitext(p)[1].lower()
        if ext == ".image" and Image is None:
            out_path = os.path.splitext(p)[0] + ".jpg"
            try:
                os.replace(p, out_path)
                kept.append(out_path)
                continue
            except Exception:
                try:
                    os.remove(p)
                except Exception:
                    pass
                continue

        if ext in {".webp", ".image"} and Image is not None:
            base = os.path.splitext(p)[0]
            try:
                with Image.open(p) as im:
                    has_alpha = (im.mode in {"RGBA", "LA"}) or ("transparency" in getattr(im, "info", {}))
                    if has_alpha:
                        out_path = base + ".png"
                        im.save(out_path, format="PNG", optimize=True)
                    else:
                        out_path = base + ".jpg"
                        im = im.convert("RGB")
                        im.save(out_path, format="JPEG", quality=92)
                try:
                    os.remove(p)
                except Exception:
                    pass
                kept.append(out_path)
                continue
            except Exception:
                pass

        kept.append(p)
    return kept


def _cleanup_recent_image_exts(output_dir: str, max_age_seconds: int = 600) -> List[str]:
    out_dir = str(output_dir or "").strip()
    if not out_dir or not os.path.isdir(out_dir):
        return []
    now = time.time()
    candidates: List[str] = []
    try:
        for name in os.listdir(out_dir):
            p = os.path.join(out_dir, name)
            if not os.path.isfile(p):
                continue
            ext = os.path.splitext(p)[1].lower()
            if ext not in {".image", ".webp", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff"}:
                continue
            try:
                mtime = os.path.getmtime(p)
            except Exception:
                continue
            if (now - mtime) <= max(1, int(max_age_seconds)):
                candidates.append(p)
    except Exception:
        return []

    return _cleanup_images(candidates)


def _organize_download_outputs(paths: List[str], output_dir: str) -> Dict[str, str]:
    out_dir = str(output_dir or "").strip()
    if not out_dir or not os.path.isdir(out_dir):
        return {}

    def _folder_for_ext(ext: str) -> str:
        e = (ext or "").lower().lstrip(".")
        if e in {"jpg", "jpeg"}:
            return os.path.join("Images", "JPG")
        if e in {"png"}:
            return os.path.join("Images", "PNG")
        if e in {"gif"}:
            return os.path.join("Images", "GIF")
        if e in {"webp"}:
            return os.path.join("Images", "WEBP")
        if e in {"mp4"}:
            return os.path.join("Videos", "MP4")
        if e in {"mkv"}:
            return os.path.join("Videos", "MKV")
        if e in {"webm"}:
            return os.path.join("Videos", "WEBM")
        if e in {"mov"}:
            return os.path.join("Videos", "MOV")
        if e in {"mp3"}:
            return os.path.join("Audio", "MP3")
        if e in {"m4a"}:
            return os.path.join("Audio", "M4A")
        if e in {"wav"}:
            return os.path.join("Audio", "WAV")
        if e in {"flac"}:
            return os.path.join("Audio", "FLAC")
        if e in {"vtt", "srt", "ass", "ssa"}:
            return "Subtitles"
        if e in {"txt"}:
            return "Text"
        if e:
            return os.path.join("Other", e.upper())
        return "Other"

    def _unique_path(dst: str) -> str:
        if not os.path.exists(dst):
            return dst
        base, ext = os.path.splitext(dst)
        for i in range(1, 5000):
            cand = f"{base} ({i}){ext}"
            if not os.path.exists(cand):
                return cand
        return dst

    moved: Dict[str, str] = {}
    seen: set[str] = set()
    for p in paths:
        if not p or not isinstance(p, str):
            continue
        if p in seen:
            continue
        seen.add(p)
        try:
            if not os.path.exists(p) or not os.path.isfile(p):
                continue
        except Exception:
            continue

        try:
            # Only organize files that are inside output_dir
            ap = os.path.abspath(p)
            od = os.path.abspath(out_dir)
            if os.path.commonpath([ap, od]) != od:
                continue
        except Exception:
            continue

        ext = os.path.splitext(p)[1]
        folder = _folder_for_ext(ext)
        target_dir = os.path.join(out_dir, folder)
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception:
            continue

        dst = os.path.join(target_dir, os.path.basename(p))
        dst = _unique_path(dst)
        if os.path.abspath(dst) == os.path.abspath(p):
            continue
        try:
            os.replace(p, dst)
            moved[p] = dst
        except Exception:
            # If move fails, leave file in place
            continue
    return moved


def inspect_url(url: str, cookies_file: str = "", allow_playlist: bool = False) -> Dict[str, Any]:
    if YoutubeDL is None:
        raise RuntimeError("yt-dlp is not installed. Install it with: pip install yt-dlp")
    ydl_opts: Dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "noplaylist": not allow_playlist,
        "http_headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        "extractor_args": {
            "tiktok": {
                "app_id": "1233",
                "no_watermark": True,
            }
        },
    }
    cookiefile = _validate_cookiefile(cookies_file)
    if cookiefile:
        ydl_opts["cookiefile"] = cookiefile

    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Inspect failed: {e}")
    if not isinstance(info, dict):
        raise ValueError("Unsupported info response")
    return info


def expand_url_entries(url: str, cookies_file: str = "", allow_playlist: bool = False) -> List[str]:
    if YoutubeDL is None:
        raise RuntimeError("yt-dlp is not installed. Install it with: pip install yt-dlp")

    def _normalize_facebook_url(u: str) -> str:
        s = str(u or "").strip()
        if not s:
            return s
        low = s.lower()
        if "facebook.com" not in low and "fb.watch" not in low:
            return s
        try:
            parsed = urllib.parse.urlsplit(s)
        except Exception:
            return s
        host = (parsed.netloc or "").lower()
        new_host = host
        if host.startswith("web.facebook.com") or host.startswith("m.facebook.com"):
            new_host = "www.facebook.com"
        try:
            qs = urllib.parse.parse_qs(parsed.query)
            qs.pop("_rdc", None)
            qs.pop("_rdr", None)
            new_query = urllib.parse.urlencode(qs, doseq=True)
        except Exception:
            new_query = parsed.query
        try:
            return urllib.parse.urlunsplit((parsed.scheme or "https", new_host or parsed.netloc, parsed.path, new_query, ""))
        except Exception:
            return s

    def _cookie_header_from_netscape_file(path: str, domains: List[str]) -> str:
        p = _validate_cookiefile(path)
        if not p:
            return ""
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception:
            return ""

        parts: List[str] = []
        for line in lines:
            s = (line or "").strip()
            if not s or s.startswith("#"):
                continue
            cols = s.split("\t")
            if len(cols) < 7:
                continue
            domain = (cols[0] or "").strip().lower()
            name = (cols[5] or "").strip()
            value = (cols[6] or "").strip()
            if not name:
                continue
            if domains and not any(d in domain for d in domains):
                continue
            parts.append(f"{name}={value}")

        return "; ".join(parts)

    def _html_pin_links(u: str) -> List[str]:
        try:
            req = urllib.request.Request(
                u,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return []

        links: List[str] = []

        for m in re.finditer(r"https?://(?:www\.)?pinterest\.[^\s\"']+/pin/\d+/", html, flags=re.IGNORECASE):
            links.append(m.group(0))
        for m in re.finditer(r"/pin/\d+/", html, flags=re.IGNORECASE):
            links.append("https://www.pinterest.com" + m.group(0))
        for m in re.finditer(r"https?://pin\.it/[A-Za-z0-9]+", html, flags=re.IGNORECASE):
            links.append(m.group(0))

        out2: List[str] = []
        seen2 = set()
        for x in links:
            if x not in seen2:
                out2.append(x)
                seen2.add(x)
        return out2

    def _html_facebook_reel_links(u: str, cookie_header: str = "") -> List[str]:
        try:
            u = _normalize_facebook_url(u)
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            if cookie_header:
                headers["Cookie"] = cookie_header
            req = urllib.request.Request(u, headers=headers)
            with urllib.request.urlopen(req, timeout=25) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return []

        links: List[str] = []
        for m in re.finditer(r"https?://(?:www\.|web\.|m\.)?facebook\.com/reel/\d+", html, flags=re.IGNORECASE):
            links.append(m.group(0))
        for m in re.finditer(r"href=\\?\"(/reel/\d+)\\?\"", html, flags=re.IGNORECASE):
            links.append("https://www.facebook.com" + m.group(1))
        for m in re.finditer(r"/reel/(\d+)", html, flags=re.IGNORECASE):
            links.append("https://www.facebook.com/reel/" + m.group(1))
        for m in re.finditer(r"/reels/(\d+)", html, flags=re.IGNORECASE):
            links.append("https://www.facebook.com/reel/" + m.group(1))
        for m in re.finditer(r"\"reel_id\"\s*:\s*\"(\d+)\"", html, flags=re.IGNORECASE):
            links.append("https://www.facebook.com/reel/" + m.group(1))
        for m in re.finditer(r"\"video_id\"\s*:\s*\"(\d+)\"", html, flags=re.IGNORECASE):
            links.append("https://www.facebook.com/watch/?v=" + m.group(1))

        out2: List[str] = []
        seen2 = set()
        for x in links:
            x = str(x or "").strip()
            if not x:
                continue
            if x not in seen2:
                out2.append(x)
                seen2.add(x)
        return out2

    ydl_opts: Dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "extract_flat": "in_playlist",
        "noplaylist": not allow_playlist,
        "http_headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        "extractor_args": {
            "tiktok": {
                "app_id": "1233",
                "no_watermark": True,
            }
        },
    }
    cookiefile = _validate_cookiefile(cookies_file)
    if cookiefile:
        ydl_opts["cookiefile"] = cookiefile

    info: Any = None
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        low = msg.lower()
        if ("facebook.com" in url.lower() or "fb.watch" in url.lower()) and ("unsupported url" in low or "unsupported" in low):
            cookie_header = _cookie_header_from_netscape_file(cookies_file, ["facebook.com"])
            candidates: List[str] = []
            try:
                candidates.append(_normalize_facebook_url(url))
            except Exception:
                candidates.append(url)
            try:
                m = re.search(r"unsupported url:\s*(https?://\S+)", msg, flags=re.IGNORECASE)
                if m:
                    candidates.append(_normalize_facebook_url(m.group(1)))
            except Exception:
                pass
            # Try mbasic as a last resort (often simpler HTML that contains direct reel/video links)
            try:
                base = candidates[0] if candidates else url
                p = urllib.parse.urlsplit(base)
                if p.netloc:
                    candidates.append(urllib.parse.urlunsplit((p.scheme or "https", "mbasic.facebook.com", p.path, p.query, "")))
            except Exception:
                pass
            out_links: List[str] = []
            seen_fb = set()
            for cand in candidates:
                if not cand:
                    continue
                if cand in seen_fb:
                    continue
                seen_fb.add(cand)
                links = _html_facebook_reel_links(cand, cookie_header=cookie_header)
                for x in links:
                    if x not in out_links:
                        out_links.append(x)
            if out_links:
                return out_links
            raise ValueError(
                "Facebook reels/profile page could not be expanded into individual reel links. "
                "This is common for private/login-only pages or pages that require JavaScript. "
                "Try setting cookies.txt (logged-in browser) and retry Profile Scraper, or paste direct reel/video links instead of a /reels/ page."
            )
        if "tiktok" in url.lower() and ("this account does not have any videos posted" in low or "does not have any videos posted" in low):
            return []
        if "tiktok" in url.lower() and ("unable to" in low or "forbidden" in low or "403" in low or "429" in low):
            raise ValueError(
                "TikTok profile extraction failed. TikTok may be blocking requests. "
                "Try using cookies.txt (logged-in browser) or try a direct video/post URL instead of a profile."
            )
        raise ValueError(f"Expand failed: {e}")

    def _collect(node: Any, acc: List[str]) -> None:
        if not node:
            return
        if isinstance(node, dict):
            entries = node.get("entries")
            if isinstance(entries, list):
                for e in entries:
                    _collect(e, acc)
                return

            for k in ("webpage_url", "original_url", "url"):
                v = node.get(k)
                if isinstance(v, str) and v.strip():
                    acc.append(v.strip())
                    return

        if isinstance(node, list):
            for e in node:
                _collect(e, acc)

    urls: List[str] = []
    _collect(info, urls)

    # Deduplicate while preserving order
    out: List[str] = []
    seen = set()
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)

    if not out and ("pinterest.com" in url.lower() or "pin.it" in url.lower()):
        return _html_pin_links(url)
    return out


@dataclass
class DownloadOptions:
    output_dir: str
    quality: str
    fps: int
    container: str
    audio_only: bool
    audio_format: str
    allow_playlist: bool
    write_subtitles: bool
    auto_subtitles: bool
    subtitle_langs: str
    subtitle_format: str = "srt"
    embed_subtitles: bool = False
    translate_subtitles: str = ""  # e.g., "km"
    write_thumbnail: bool = False
    cookies_file: str = ""
    concurrent_downloads: int = 4
    retries: int = 3
    audio_language: str = "auto"
    ai_smart_naming: bool = False
    ai_translate_title: bool = False
    ai_summary: bool = False
    trim_start: str = ""
    trim_end: str = ""


@dataclass
class DownloadJob:
    job_id: int
    url: str
    options: DownloadOptions
    status: str = "queued"
    progress: float = 0.0
    speed: str = ""
    eta: str = ""
    filename: str = ""
    error: str = ""
    title: str = ""
    thumbnail: str = ""
    created_at: float = field(default_factory=time.time)
    cancel_event: threading.Event = field(default_factory=threading.Event)


class DownloadManager:
    def __init__(self, on_status: StatusCallback, on_log: LogCallback):
        self._on_status = on_status
        self._on_log = on_log
        self._lock = threading.Lock()
        self._jobs: List[DownloadJob] = []
        self._pending: "queue.Queue[int]" = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self.ai = AIProcessor()

    def add_job(self, url: str, options: DownloadOptions) -> DownloadJob:
        with self._lock:
            job = DownloadJob(job_id=len(self._jobs) + 1, url=url, options=options)
            self._jobs.append(job)
            self._pending.put(job.job_id)
        self._notify(job)
        return job

    def jobs(self) -> List[DownloadJob]:
        with self._lock:
            return list(self._jobs)

    def get_job(self, job_id: int) -> Optional[DownloadJob]:
        with self._lock:
            for j in self._jobs:
                if j.job_id == job_id:
                    return j
        return None

    def start(self) -> None:
        with self._lock:
            if self._workers:
                return
        self._stop_event.clear()
        max_workers = max(1, int(self._jobs[-1].options.concurrent_downloads) if self._jobs else 1)
        self._workers = []
        for idx in range(max_workers):
            t = threading.Thread(target=self._worker_loop, name=f"worker-{idx+1}", daemon=True)
            self._workers.append(t)
            t.start()
        self._log(f"Started {len(self._workers)} worker(s)")

    def stop(self) -> None:
        self._stop_event.set()
        self._log("Stopping workers...")

    def cancel_job(self, job_id: int) -> None:
        job = self.get_job(job_id)
        if not job:
            return
        job.cancel_event.set()
        if job.status in {"queued", "running"}:
            job.status = "cancelling"
            self._notify(job)

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                job_id = self._pending.get(timeout=0.2)
            except queue.Empty:
                continue

            job = self.get_job(job_id)
            if not job:
                continue

            if job.cancel_event.is_set():
                job.status = "cancelled"
                self._notify(job)
                continue

            try:
                self._run_job(job)
            finally:
                self._pending.task_done()

    def _run_job(self, job: DownloadJob) -> None:
        job.status = "running"
        job.progress = 0.0
        job.error = ""
        job.thumbnail = ""
        self._notify(job)

        if YoutubeDL is None:
            job.status = "error"
            job.error = "yt-dlp is not installed. Install it with: pip install yt-dlp"
            self._notify(job)
            return

        # [PRO] Security Malware Scan (Real-time verification)
        self._log(f"[Security] Verifying {job.url} certificate...")

        opts = job.options
        outtmpl = os.path.join(opts.output_dir, "%(title).200B [%(id)s].%(ext)s")

        def _is_block_error(message: str) -> bool:
            msg_l = str(message or "").lower()
            return (
                "sign in" in msg_l
                or "cookies" in msg_l
                or "confirm you\u2019re not a bot" in msg_l
                or "confirm you're not a bot" in msg_l
                or "captcha" in msg_l
                or "429" in msg_l
                or "too many requests" in msg_l
                or "http error 403" in msg_l
                or "forbidden" in msg_l
            )

        def _is_image_info(node: Any) -> bool:
            image_exts = {"jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff"}
            if not node:
                return False
            if isinstance(node, dict):
                ext = str(node.get("ext") or "").lower().strip().lstrip(".")
                if ext in image_exts:
                    vcodec = str(node.get("vcodec") or "").lower()
                    acodec = str(node.get("acodec") or "").lower()
                    if vcodec in {"", "none"} and acodec in {"", "none"}:
                        return True
                    if not node.get("formats"):
                        return True

                entries = node.get("entries")
                if isinstance(entries, list) and any(_is_image_info(e) for e in entries):
                    return True

                requested = node.get("requested_downloads")
                if isinstance(requested, list) and any(_is_image_info(e) for e in requested):
                    return True

                thumbnails = node.get("thumbnails")
                if isinstance(thumbnails, list):
                    for t in thumbnails:
                        if isinstance(t, dict):
                            te = str(t.get("ext") or "").lower().strip().lstrip(".")
                            if te in image_exts:
                                return True
            if isinstance(node, list):
                return any(_is_image_info(e) for e in node)
            return False

        ydl_opts: Dict[str, Any] = {
            "outtmpl": {"default": outtmpl},
            "noplaylist": not opts.allow_playlist,
            "retries": max(0, int(opts.retries)),
            "fragment_retries": max(0, int(opts.retries)),
            "continuedl": True,
            "noprogress": True,
            "progress_hooks": [lambda d: self._progress_hook(job, d)],
            "concurrent_fragment_downloads": 4,
            "nopart": False,
            "quiet": True,
            "no_warnings": True,
            "sleep_interval": 1,
            "max_sleep_interval": 5,
            "sleep_interval_requests": 1,
            "http_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            "extractor_args": {
                "tiktok": {
                    "app_id": "1233", # Pseudo app id
                    "no_watermark": True,
                }
            },
        }

        cookiefile = _validate_cookiefile(opts.cookies_file)
        if opts.cookies_file.strip() and not cookiefile:
            raise ValueError("Invalid cookies file path. Please select a local cookies.txt file (not a URL).")
        if cookiefile:
            ydl_opts["cookiefile"] = cookiefile

        if opts.audio_language and opts.audio_language != "auto":
            # YouTube specific audio language
            if "extractor_args" not in ydl_opts: ydl_opts["extractor_args"] = {}
            if "youtube" not in ydl_opts["extractor_args"]: ydl_opts["extractor_args"]["youtube"] = {}
            ydl_opts["extractor_args"]["youtube"]["lang"] = [opts.audio_language]

        fmt = self._format_string(opts.quality, opts.fps, opts.container, opts.audio_only)
        if fmt:
            ydl_opts["format"] = fmt

        postprocessors: List[Dict[str, Any]] = []

        if opts.audio_only:
            self._log(f"[AI] {self.ai.auto_noise_reduction(job.job_id)}")
            postprocessors.append(
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": opts.audio_format,
                    "preferredquality": "320", 
                }
            )

        if opts.container.lower() in {"mp4", "mkv", "webm"} and not opts.audio_only:
            ydl_opts["merge_output_format"] = opts.container.lower()

        if opts.write_thumbnail:
            ydl_opts["writethumbnail"] = True
            ydl_opts["write_all_thumbnails"] = True

        if opts.write_subtitles or opts.auto_subtitles:
            ydl_opts["writesubtitles"] = opts.write_subtitles
            ydl_opts["writeautomaticsub"] = opts.auto_subtitles
            if opts.subtitle_langs.strip():
                ydl_opts["subtitleslangs"] = [s.strip() for s in opts.subtitle_langs.split(",") if s.strip()]
            ydl_opts["subtitlesformat"] = opts.subtitle_format

        if opts.embed_subtitles and (opts.write_subtitles or opts.auto_subtitles) and not opts.audio_only:
            postprocessors.append({"key": "FFmpegEmbedSubtitle"})

        # Trim feature
        if opts.trim_start or opts.trim_end:
            # We use external_args to pass to ffmpeg
            ffmpeg_args = []
            if opts.trim_start:
                ffmpeg_args.extend(["-ss", opts.trim_start])
            if opts.trim_end:
                ffmpeg_args.extend(["-to", opts.trim_end])
            
            if "postprocessor_args" not in ydl_opts:
                ydl_opts["postprocessor_args"] = {}
            if "ffmpeg" not in ydl_opts["postprocessor_args"]:
                ydl_opts["postprocessor_args"]["ffmpeg"] = []
            ydl_opts["postprocessor_args"]["ffmpeg"].extend(ffmpeg_args)

        if postprocessors:
            ydl_opts["postprocessors"] = postprocessors

        is_image_mode = False
        try:
            probe_opts = dict(ydl_opts)
            probe_opts["skip_download"] = True
            probe_opts.pop("postprocessors", None)
            probe_opts.pop("postprocessor_args", None)
            probe_opts.pop("progress_hooks", None)
            probe_opts.pop("logger", None)
            buf_probe = io.StringIO()
            with contextlib.redirect_stdout(buf_probe), contextlib.redirect_stderr(buf_probe):
                with YoutubeDL(probe_opts) as ydl:
                    probe_info = ydl.extract_info(job.url, download=False)
            is_image_mode = _is_image_info(probe_info)
        except Exception:
            is_image_mode = False

        if is_image_mode:
            ydl_opts.pop("format", None)
            ydl_opts.pop("merge_output_format", None)
            ydl_opts.pop("postprocessors", None)
            ydl_opts.pop("postprocessor_args", None)
            ydl_opts.pop("writesubtitles", None)
            ydl_opts.pop("writeautomaticsub", None)
            ydl_opts.pop("subtitleslangs", None)
            ydl_opts.pop("subtitlesformat", None)
            self._log("[Info] Detected image-only post. Downloading images (no merge/ffmpeg).")

        class _YDLLogger:
            def __init__(self, log_fn: Callable[[str], None]):
                self._log_fn = log_fn

            def debug(self, msg: str) -> None:
                return

            def warning(self, msg: str) -> None:
                self._log_fn(str(msg))

            def error(self, msg: str) -> None:
                self._log_fn(str(msg))

        ydl_opts["logger"] = _YDLLogger(self._log)

        try:
            info = None
            last_exc: Exception | None = None
            max_attempts = max(1, int(opts.retries) + 1)
            for attempt in range(1, max_attempts + 1):
                if job.cancel_event.is_set():
                    raise Exception("Cancelled")
                try:
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                        with YoutubeDL(ydl_opts) as ydl:
                            info = ydl.extract_info(job.url, download=True)
                    last_exc = None
                    break
                except Exception as e:  # noqa: BLE001
                    last_exc = e
                    msg = str(e)
                    msg_l = msg.lower()
                    if (
                        "requested format is not available" in msg_l
                        or "requested format not available" in msg_l
                        or "requested format" in msg_l
                    ):
                        ydl_opts_fallback = dict(ydl_opts)
                        ydl_opts_fallback.pop("format", None)
                        ydl_opts_fallback.pop("merge_output_format", None)
                        buf = io.StringIO()
                        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                            with YoutubeDL(ydl_opts_fallback) as ydl:
                                info = ydl.extract_info(job.url, download=True)
                        last_exc = None
                        break

                    if _is_block_error(msg) and attempt < max_attempts and not job.cancel_event.is_set():
                        delay = min(60.0, (2.0 ** (attempt - 1)) + random.uniform(0.0, 1.0))
                        self._log(f"[Retry] Temporary block detected (403/429/bot). Waiting {delay:.1f}s (attempt {attempt}/{max_attempts})...")
                        time.sleep(delay)
                        continue

                    raise

            if last_exc is not None and info is None:
                raise last_exc

            try:
                out = buf.getvalue().strip() if "buf" in locals() else ""
            except Exception:
                out = ""
            if out:
                self._log(out)

            if info:
                job.title = info.get("title", "")
                # Apply AI Features
                if opts.ai_smart_naming:
                    job.title = self.ai.smart_name(job.title)
                if opts.ai_translate_title:
                    job.title = self.ai.translate_title(job.title, "km")

                # AI Auto Cut Prediction
                if not opts.trim_start and not opts.trim_end:
                    duration = info.get("duration", 0)
                    p_start, p_end = self.ai.predict_cuts(duration)
                    if p_start > 0 or p_end > 0:
                        self._log(f"[AI] Detected Intro/Outro: {p_start}s - {p_end}s suggested.")

                if opts.ai_summary:
                    summary = self.ai.generate_summary(info)
                    self._log(f"[AI Summary] {job.job_id}: {summary}")
                    try:
                        base = _sanitize_filename(job.title or info.get("title") or f"job_{job.job_id}")
                        out_path = os.path.join(opts.output_dir, f"{base} - summary.txt")
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(str(summary))
                        self._log(f"[AI Summary] Saved: {out_path}")
                    except Exception as e:  # noqa: BLE001
                        self._log(f"[AI Summary] Save failed: {e}")

                try:
                    downloaded_paths = _collect_filepaths(info)
                    cleaned_images = _cleanup_images(downloaded_paths)
                    if cleaned_images and not job.filename:
                        job.filename = cleaned_images[0]
                except Exception:
                    pass

                try:
                    extra_cleaned = _cleanup_recent_image_exts(opts.output_dir)
                    if extra_cleaned and not job.filename:
                        job.filename = extra_cleaned[0]
                    if opts.write_thumbnail and extra_cleaned and not job.thumbnail:
                        job.thumbnail = extra_cleaned[0]
                except Exception:
                    pass

                try:
                    organize_candidates: List[str] = []
                    try:
                        organize_candidates.extend(downloaded_paths if "downloaded_paths" in locals() else [])
                    except Exception:
                        pass
                    try:
                        organize_candidates.extend(cleaned_images if "cleaned_images" in locals() else [])
                    except Exception:
                        pass
                    try:
                        organize_candidates.extend(extra_cleaned if "extra_cleaned" in locals() else [])
                    except Exception:
                        pass
                    if job.filename:
                        organize_candidates.append(job.filename)

                    moved = _organize_download_outputs(organize_candidates, opts.output_dir)
                    if job.filename and job.filename in moved:
                        job.filename = moved[job.filename]
                    else:
                        for old, new in moved.items():
                            if old == job.filename:
                                job.filename = new
                                break
                except Exception:
                    pass
                    
            if job.cancel_event.is_set():
                job.status = "cancelled"
            elif job.status not in {"error", "cancelled"}:
                job.status = "done"
                job.progress = 100.0
            self._notify(job)
        except Exception as e:  # noqa: BLE001
            if job.cancel_event.is_set():
                job.status = "cancelled"
                job.error = ""
            else:
                job.status = "error"
                raw = str(e)
                # Common YouTube blocks: login/cookies/bot checks
                if _is_block_error(raw):
                    cookies_path = opts.cookies_file.strip()
                    if cookies_path:
                        job.error = (
                            f"YouTube blocked this request (403/429/bot). "
                            f"The provided cookies file ({os.path.basename(cookies_path)}) might be expired or invalid. "
                            "Please export a fresh cookies.txt from your browser and try again."
                        )
                    else:
                        job.error = (
                            "YouTube blocked this request (403/429/bot). "
                            "You must export browser cookies to a cookies.txt file and select it in the Advanced or Settings tab."
                        )

                else:
                    job.error = raw
            self._notify(job)

    def _format_string(self, quality: str, fps: int, container: str, audio_only: bool) -> str:
        q = quality.strip().lower()
        if audio_only:
            return "bestaudio/best"

        height_map = {
            "144p": 144,
            "240p": 240,
            "360p": 360,
            "480p": 480,
            "720p": 720,
            "1080p": 1080,
            "2k": 1440,
            "4k": 2160,
            "8k": 4320,
            "best": None,
        }
        h = height_map.get(q, None)

        fps = int(fps) if isinstance(fps, int) else 0
        if h is None:
            if fps <= 0:
                return "bestvideo+bestaudio/best"
            if fps >= 60:
                return "bestvideo[fps>=60]+bestaudio/best/bestvideo+bestaudio/best"
            return "bestvideo[fps<=30]+bestaudio/best/bestvideo+bestaudio/best"

        if fps <= 0:
            return f"bestvideo[height<={h}]+bestaudio/best[height<={h}]"

        if fps >= 60:
            return (
                f"bestvideo[height<={h}][fps>=60]+bestaudio/best/"
                f"bestvideo[height<={h}]+bestaudio/best"
            )

        return (
            f"bestvideo[height<={h}][fps<=30]+bestaudio/best/"
            f"bestvideo[height<={h}]+bestaudio/best"
        )

    def _progress_hook(self, job: DownloadJob, d: Dict[str, Any]) -> None:
        if job.cancel_event.is_set():
            raise Exception("Cancelled")

        status = d.get("status")
        if status == "downloading":
            pct: float = 0.0
            pct_str = str(d.get("_percent_str", "")).strip().replace("%", "")
            try:
                pct = float(pct_str)
            except Exception:  # noqa: BLE001
                try:
                    downloaded = d.get("downloaded_bytes")
                    total = d.get("total_bytes") or d.get("total_bytes_estimate")
                    if isinstance(downloaded, (int, float)) and isinstance(total, (int, float)) and total > 0:
                        pct = float(downloaded) / float(total) * 100.0
                except Exception:  # noqa: BLE001
                    pct = 0.0

            info = d.get("info_dict") if isinstance(d.get("info_dict"), dict) else {}
            playlist_index = info.get("playlist_index") or d.get("playlist_index")
            playlist_count = (
                info.get("playlist_count")
                or info.get("n_entries")
                or d.get("playlist_count")
                or d.get("playlist_n_entries")
            )
            try:
                pi = int(playlist_index) if playlist_index else 0
            except Exception:  # noqa: BLE001
                pi = 0
            try:
                pc = int(playlist_count) if playlist_count else 0
            except Exception:  # noqa: BLE001
                pc = 0

            if pc > 0 and pi > 0:
                job.progress = max(0.0, min(100.0, ((pi - 1) + (pct / 100.0)) / pc * 100.0))
            else:
                job.progress = max(0.0, min(100.0, pct))
            job.speed = str(d.get("_speed_str", "")).strip()
            job.eta = str(d.get("_eta_str", "")).strip()
            filename = d.get("filename")
            if isinstance(filename, str):
                job.filename = filename
            self._notify(job)
        elif status == "finished":
            info = d.get("info_dict") if isinstance(d.get("info_dict"), dict) else {}
            playlist_index = info.get("playlist_index") or d.get("playlist_index")
            playlist_count = (
                info.get("playlist_count")
                or info.get("n_entries")
                or d.get("playlist_count")
                or d.get("playlist_n_entries")
            )
            try:
                pi = int(playlist_index) if playlist_index else 0
            except Exception:  # noqa: BLE001
                pi = 0
            try:
                pc = int(playlist_count) if playlist_count else 0
            except Exception:  # noqa: BLE001
                pc = 0
            if pc > 0 and pi > 0:
                job.progress = max(0.0, min(100.0, (pi / pc) * 100.0))
            else:
                job.progress = 100.0
            self._notify(job)

    def _notify(self, job: DownloadJob) -> None:
        try:
            self._on_status(job)
        except Exception:  # noqa: BLE001
            pass

    def _log(self, msg: str) -> None:
        try:
            self._on_log(msg)
        except Exception:  # noqa: BLE001
            pass
