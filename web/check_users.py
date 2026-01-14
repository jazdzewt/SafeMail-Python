from app import app, db
from models import User

def show_users():
    with app.app_context():
        users = User.query.all()
        if not users:
            print("Brak użytkowników w bazie.")
            return

        print(f"{'ID':<38} | {'Username':<15}")
        print("-" * 60)
        for u in users:
            print(f"{u.id:<38} | {u.username:<15}")

if __name__ == "__main__":
    show_users()
