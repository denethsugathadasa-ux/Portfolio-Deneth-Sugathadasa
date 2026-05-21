# Mandatory Access Control (MAC) Implementation
# Principle: Access is determined by system-assigned security labels

CLEARANCE_LEVELS = {
    "PUBLIC": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP_SECRET": 4
}

users = {
    "alice": {"clearance": "TOP_SECRET", "full_name": "Alice"},
    "bob": {"clearance": "SECRET", "full_name": "Bob"},
    "charlie": {"clearance": "CONFIDENTIAL", "full_name": "Charlie"},
    "dave": {"clearance": "PUBLIC", "full_name": "Dave"}
}

documents = {
    "1": {"name": "Top Secret Intelligence Report", "classification": "TOP_SECRET"},
    "2": {"name": "Secret Operational Memo", "classification": "SECRET"},
    "3": {"name": "Confidential Budget Brief", "classification": "CONFIDENTIAL"},
    "4": {"name": "Public Announcement", "classification": "PUBLIC"},
    "5": {"name": "Secret Personnel File", "classification": "SECRET"}
}

def print_banner():
    print("\n" + "=" * 60)
    print("   MAC System - Government Security Clearance Portal")
    print("=" * 60)

def print_users():
    print("\nRegistered Users:")
    print("-" * 40)
    for username, info in users.items():
        print(f"  {info['full_name']:<12} | Clearance: {info['clearance']}")

def print_documents():
    print("\nAvailable Documents:")
    print("-" * 40)
    for doc_id, doc in documents.items():
        print(f"  [{doc_id}] {doc['name']:<35} | Classification: {doc['classification']}")

def check_access(username, doc_id):
    user = users.get(username.lower())
    doc = documents.get(doc_id)

    if not user:
        print(f"\n  [!] Unknown user '{username}' - access denied.")
        return
    if not doc:
        print(f"\n  [!] Invalid document ID '{doc_id}' - document not found.")
        return

    user_level = CLEARANCE_LEVELS[user["clearance"]]
    doc_level = CLEARANCE_LEVELS[doc["classification"]]

    print(f"\n  User:       {user['full_name']} (Clearance: {user['clearance']})")
    print(f"  Document:   {doc['name']} (Classification: {doc['classification']})")
    print(f"  " + "-" * 50)

    if user_level >= doc_level:
        print(f"   ACCESS GRANTED - clearance level sufficient")
    else:
        print(f"   ACCESS DENIED  - insufficient clearance level")
        print(f"    Required: {doc['classification']} | Your level: {user['clearance']}")

def main():
    print_banner()
    print("\nWelcome to the Mandatory Access Control System.")
    print("Access is strictly enforced based on security clearance levels.")

    while True:
        print_users()
        print_documents()

        print("\n" + "-" * 60)
        username = input("  Enter username (or 'quit' to exit): ").strip()
        if username.lower() == "quit":
            print("\n  System exiting. Goodbye.\n")
            break

        doc_id = input("  Enter document number to access: ").strip()
        check_access(username, doc_id)

        print("\n  " + "=" * 58)
        again = input("  Try another access request? (y/n): ").strip().lower()
        if again != "y":
            print("\n  Session ended. All access attempts have been logged.\n")
            break

if __name__ == "__main__":
    main()