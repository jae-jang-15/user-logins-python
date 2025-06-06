import hashlib
VALID_CREDENTIALS = {
        'robert':'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', #password123
        'jae'   :'9b8769a4a742959a2d0298c36fb70623f2dfacda8436237df08d8dfd5b37374c', #pass123
        'bob'   :'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'  #123
}

def is_valid_credentials(username, password):

    if username in VALID_CREDENTIALS and password in VALID_CREDENTIALS[username]:
        return True
    else:
        return False

def sha256_hash(input_string):
    """
    Generates the SHA-256 hash of a given string.

    Args:
        input_string: The string to be hashed.

    Returns:
        The SHA-256 hash of the input string as a hexadecimal string.
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


def main():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    hashed_password = sha256_hash(password)

    if is_valid_credentials(username, hashed_password):
        print("Login successful!")
        print("Access granted.")
    else:
        print("Login failed!")
        print("Access denied.")


if __name__ == "__main__":
    main()