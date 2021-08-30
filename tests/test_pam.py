from pam import authenticate


def test_PamAuthenticator():
    authenticate('a', 'b')
