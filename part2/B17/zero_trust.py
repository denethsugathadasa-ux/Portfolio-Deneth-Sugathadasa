# Zero Trust RBAC Implementation
# Principle: Never trust, always verify — every access request is checked

users = {
    "alice": {"role": "admin", "verified": True},
    "bob": {"role": "developer", "verified": True},
    "charlie": {"role": "intern", "verified": True},
    "eve": {"role": "developer", "verified": False},  # unverified user
}

permissions = {
    "admin": ["read", "write", "delete", "manage_users"],
    "developer": ["read", "write"],
    "intern": ["read"],
}

def verify_identity(username):
    user = users.get(username)
    if not user:
        return False, "User does not exist"
    if not user["verified"]:
        return False, f"User '{username}' is not verified — access denied (Zero Trust)"
    return True, user["role"]

def request_access(username, action):
    print(f"\n[ACCESS REQUEST] User: '{username}' | Action: '{action}'")
    verified, result = verify_identity(username)
    if not verified:
        print(f"[DENIED] {result}")
        return
    role = result
    allowed = permissions.get(role, [])
    if action in allowed:
        print(f"[GRANTED] '{username}' ({role}) is allowed to '{action}'")
    else:
        print(f"[DENIED] '{username}' ({role}) does not have permission to '{action}'")

# --- Test Cases ---
print("=" * 55)
print("   Zero Trust Role-Based Access Control System")
print("=" * 55)

request_access("alice", "manage_users")   # admin — should pass
request_access("alice", "delete")         # admin — should pass
request_access("bob", "write")            # developer — should pass
request_access("bob", "delete")           # developer — should fail
request_access("charlie", "write")        # intern — should fail
request_access("eve", "read")             # unverified — should fail
request_access("ghost", "read")           # nonexistent user — should fail

print("\n" + "=" * 55)
print("Evaluation: Zero Trust enforced at every access point.")
print("No user is trusted by default — identity and role")
print("are verified before every single request.")
print("=" * 55)