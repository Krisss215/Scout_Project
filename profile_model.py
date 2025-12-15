from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Profile:
    full_name: str = ""
    email: str = ""
    location: str = ""

    target_titles: List[str] = field(default_factory=list)
    industries: List[str] = field(default_factory=list)
    employment_types: List[str] = field(default_factory=list)

    languages: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    exclude_keywords: List[str] = field(default_factory=list)

    salary_expectation: Optional[str] = None
