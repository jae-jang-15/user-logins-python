import hashlib
import yaml


def load_yaml_file(file_path):
    """
    Load the yaml file and reads the file.
    
    Args:
        file_path: The string name of a file.

    Retruns:
        The yaml file data
    """
    with open(file_path, 'r') as fp:
        try:
            yaml_data = yaml.safe_load(fp)
            return yaml_data
        except yaml.YAMLError as exception:
            print(exception)
            return None


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


def is_valid_credentials(username, password):
    """
    Compare the username and the password to the database

    Args:
        username
        password: hashed password 

    Returns:
        Boolean value 
    """
    file_path = 'credentials.yaml'
    yaml_content = load_yaml_file(file_path='credentials.yaml')
    
    if yaml_content:
        for content in yaml_content:
            if content['username'] == username:
                if content['password_hash'] == password:
                    return True
    
    return False


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