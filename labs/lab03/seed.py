import json
import logging
import sqlite3
from pathlib import Path
from labs.lab03.database import get_connection

BASE_DIR = Path(__file__).resolve().parent
SEED_FILE = BASE_DIR / "data" / "seed.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def seed_database() -> None:
    """Заповнити порожню базу початковими даними з seed.json в одній транзакції."""
    if not SEED_FILE.exists():
        logger.error("Файл seed.json не знайдено!")
        return

    with open(SEED_FILE, encoding="utf-8") as f:
        data = json.load(f)

    categories = data.get("categories", [])
    records = data.get("records", [])

    connection = get_connection()
    try:
        with connection:
            cursor = connection.cursor()
            
            # Перевірка: якщо в таблиці categories вже є дані — не перезаповнювати
            cursor.execute("SELECT COUNT(*) FROM categories")
            if cursor.fetchone()[0] > 0:
                logger.info("База вже містить дані. Початкове заповнення скасовано.")
                return

            # Вставляємо категорії з їхніми id з JSON
            for cat in categories:
                cursor.execute(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    (cat["id"], cat["name"]),
                )

            # Вставляємо записи
            for rec in records:
                cursor.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        rec["code"],
                        rec["title"],
                        rec["category_id"],
                        rec["value"],
                        rec["status"],
                    ),
                )
        logger.info("Базу даних успішно заповнено початковими даними!")
    except sqlite3.Error as e:
        logger.error(f"Помилка під час заповнення бази: {e}")
    finally:
        connection.close()


if __name__ == "__main__":
    seed_database()