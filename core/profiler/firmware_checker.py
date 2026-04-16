import re
from datetime import datetime

def estimate_firmware_age(banners: list[str]) -> dict:
    """
    Look through service banners for a year.
    If found and its 3+ years old, flag as outdated.
    Example banner: 'Server: Hikvision-Webs/2.0 BuildDate: Jan 15 2019'
    """
    year_pattern = re.compile(r"(20\d{2})")
    oldest_year = None

    for banner in banners:
        for match in year_pattern.findall(banner):
            year = int(match)
            if 2000 <= year <= datetime.now().year:
                if oldest_year is None or year < oldest_year:
                    oldest_year = year

    if oldest_year:
        age = datetime.now().year - oldest_year
        return {
            "estimated_year": oldest_year,
            "age_years": age,
            "is_outdated": age >= 3
        }

    return {
        "estimated_year": None,
        "age_years": None,
        "is_outdated": False
    }
