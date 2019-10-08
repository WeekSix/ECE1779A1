from app.db_util import get_user, add_user
import app.mysalt as mysalt
def register(username, password):
    """Register user if username is available
       Return True if registration is successful
       Return False when username is taken
    """
    res=get_user(username)
    if res is not None:
        return False
    salt=mysalt.generate_salt()
    salted_password=mysalt.salted_password(salt,password)
    add_user(username,salt,salted_password)
    return True


def login(username, password):
    '''Verifies username and password. Return True if login is successful. Return False otherwise'''
    res=get_user(username)
    if res is None:
        return False
    else:
        salt=str(res['salt'])#response are unicode strings, cast them into str first
        return mysalt.salted_password(salt,password)==str(res['password'])
