#!/usr/bin/env python3
"""
User management CLI for BugBounty AutoScanner.
Run this to create/manage user accounts.
"""

import json
import os
import sys
import getpass
from werkzeug.security import generate_password_hash, check_password_hash

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

def load_users():
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    print(f"  ✓ Saved to {USERS_FILE}")

def list_users():
    users = load_users()
    if not users:
        print("  No users found.")
        return
    print(f"\n  {'Username':<20} {'Role':<10} {'Active':<8} {'Created'}")
    print("  " + "─" * 60)
    for name, data in users.items():
        role    = data.get("role", "user")
        active  = "✓" if data.get("active", True) else "✗"
        created = data.get("created_at", "—")[:10]
        print(f"  {name:<20} {role:<10} {active:<8} {created}")

def create_user():
    print("\n  ── Create User ──")
    username = input("  Username: ").strip()
    if not username:
        print("  Username cannot be empty")
        return
    users = load_users()
    if username in users:
        print(f"  User '{username}' already exists")
        return
    role = input("  Role [user/admin] (default: user): ").strip() or "user"
    password = getpass.getpass("  Password: ")
    if len(password) < 6:
        print("  Password must be at least 6 characters")
        return
    confirm = getpass.getpass("  Confirm password: ")
    if password != confirm:
        print("  Passwords do not match")
        return
    users[username] = {
        "password":   generate_password_hash(password),
        "role":       role,
        "active":     True,
        "created_at": __import__("datetime").datetime.utcnow().isoformat(),
    }
    save_users(users)
    print(f"  ✓ User '{username}' created (role: {role})")

def change_password():
    print("\n  ── Change Password ──")
    users = load_users()
    username = input("  Username: ").strip()
    if username not in users:
        print(f"  User '{username}' not found")
        return
    password = getpass.getpass("  New password: ")
    if len(password) < 6:
        print("  Password must be at least 6 characters")
        return
    confirm = getpass.getpass("  Confirm new password: ")
    if password != confirm:
        print("  Passwords do not match")
        return
    users[username]["password"] = generate_password_hash(password)
    save_users(users)
    print(f"  ✓ Password updated for '{username}'")

def delete_user():
    print("\n  ── Delete User ──")
    users = load_users()
    username = input("  Username to delete: ").strip()
    if username not in users:
        print(f"  User '{username}' not found")
        return
    confirm = input(f"  Delete '{username}'? [y/N]: ").strip().lower()
    if confirm == "y":
        del users[username]
        save_users(users)
        print(f"  ✓ User '{username}' deleted")

def toggle_user():
    print("\n  ── Toggle Active Status ──")
    users = load_users()
    username = input("  Username: ").strip()
    if username not in users:
        print(f"  User '{username}' not found")
        return
    current = users[username].get("active", True)
    users[username]["active"] = not current
    save_users(users)
    status = "activated" if not current else "deactivated"
    print(f"  ✓ User '{username}' {status}")


MENU = """
╔══════════════════════════════════════╗
║   BugBounty Scanner — User Manager  ║
╚══════════════════════════════════════╝
  1. List users
  2. Create user
  3. Change password
  4. Delete user
  5. Toggle active/inactive
  6. Exit
"""

if __name__ == "__main__":
    print(MENU)
    while True:
        try:
            choice = input("  Select [1-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye!")
            break

        if   choice == "1": list_users()
        elif choice == "2": create_user()
        elif choice == "3": change_password()
        elif choice == "4": delete_user()
        elif choice == "5": toggle_user()
        elif choice == "6": print("  Bye!"); break
        else: print("  Invalid choice")
        print()
