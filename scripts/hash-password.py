from getpass import getpass
from werkzeug.security import generate_password_hash
p=getpass('Recovery-lösenord: ')
print(generate_password_hash(p))
