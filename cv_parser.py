from pathlib import Path
from typing import Union

import pdfplumber
from docx import Document


def extract_text_from_pdf(path: Union[str, Path]) -> str:
    path = Path(path)
    text_chunks = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_chunks.append(page_text)
    return "\n".join(text_chunks)


def extract_text_from_docx(path: Union[str, Path]) -> str:
    path = Path(path)
    doc = Document(path)
    text_chunks = [para.text for para in doc.paragraphs if para.text.strip()]
    return "\n".join(text_chunks)


def extract_cv_text(path: Union[str, Path]) -> str:
    """
    Detects file type and extracts plain text from CV.
    Supports .pdf and .docx.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return extract_text_from_pdf(path)
    elif suffix == ".docx":
        return extract_text_from_docx(path)
    else:
        raise ValueError(f"Unsupported CV format: {suffix}. Use PDF or DOCX.")
