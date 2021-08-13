import sys
import requests
import hashlib


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, check the api and try again!")
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_pwned_api(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = check_pwned_api(password)
        if count:
            print(f"Password {password} was found {count} times, you should probably change your password!")
        else:
            print(f"Password {password} was NOT found. Carry on!")
    return "done!"


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

