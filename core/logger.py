import logging
import os
from rich.logging import RichHandler

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        RichHandler(rich_tracebacks=True, show_path=False),
        logging.FileHandler("logs/xauth.log")
    ]
)

logger = logging.getLogger("xauth")