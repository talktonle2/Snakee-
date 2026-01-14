import re

class AIProcessor:
    def __init__(self):
        # Khmer title translation dictionary (mock)
        self.km_translations = {
            "Official Music Video": "វីដេអូចម្រៀងផ្លូវការ",
            "Shorts": "វីដេអូខ្លី",
            "Trailer": "វីដេអូខ្លីនៃរឿង",
            "Tutorial": "ការបង្ហាញបច្ចេកទេស",
            "Live Stream": "ការផ្សាយបន្តផ្ទាល់",
            "Podcast": "ផតខាស",
            "Highlights": "ចំណុចសំខាន់ៗ",
            "Full Episode": "ភាគពេញ",
            "Reaction": "ប្រតិកម្ម",
            "Review": "ការត្រួតពិនិត្យឡើងវិញ",
        }

    def smart_name(self, title: str) -> str:
        """Cleans title by removing common junk."""
        junk = [
            r"\[.*?\]",                   # Square brackets
            r"\(.*?\)",                   # Parentheses
            r"\|.*",                      # Everything after pipe
            r"-.*",                       # Everything after dash
            r"\(Official.*?\)",           # (Official Music Video)
            r"1080p|720p|4k|8k|hdr",      # Resolution
            r"full hd|fullhd",
            r"x264|h264|x265|hevc",      # Codecs
            r"eng sub|subtitles",        # Subs
        ]
        new_title = title
        for pattern in junk:
            new_title = re.sub(pattern, "", new_title, flags=re.IGNORECASE)
        
        # Trim and remove double spaces
        new_title = re.sub(r"\s+", " ", new_title).strip()
        return new_title if new_title else title

    def translate_title(self, title: str, target_lang: str = "km") -> str:
        """Mock translation for title using dictionary."""
        if target_lang != "km":
            return title
            
        new_title = title
        for en, km in self.km_translations.items():
            pattern = re.compile(re.escape(en), re.IGNORECASE)
            new_title = pattern.sub(km, new_title)
        
        return new_title

    def generate_summary(self, info: dict) -> str:
        """Generates a smart summary from video metadata."""
        title = info.get("title", "Unknown")
        uploader = info.get("uploader", "Unknown")
        views = info.get("view_count", 0)
        duration = info.get("duration", 0)
        categories = ", ".join(info.get("categories", []))
        
        summary = f"--- AI Analysis Summary ---\n"
        summary += f"Title: {title}\n"
        summary += f"Creator: {uploader}\n"
        summary += f"Duration: {int(duration)//60}:{int(duration)%60:02d}\n"
        summary += f"Category: {categories if categories else 'N/A'}\n"
        summary += f"Reach: {views:,} views\n"
        summary += "--- AI Insights ---\n"
        summary += "Content appears to be professionally produced with high engagement potential."
        return summary

    def auto_noise_reduction(self, job_id: int):
        """Mock AI Noise reduction status."""
        return f"AI DeepClean v2.1: Noise removal applied to Job {job_id}"


    def predict_cuts(self, duration: float):
        """Predict Intro/Outro cuts based on typical patterns."""
        if not duration: return (0, 0)
        intro = 5.0 if duration > 60 else 0
        outro = 10.0 if duration > 300 else 5.0
        return (intro, outro)

    def translate_subtitle(self, text: str, target: str = "km") -> str:
        """Mock subtitle translation."""
        # In a real app, this would call a translation API
        return f"[{target}] {text}"
