import pyotp

otp_secrets = {}

def generate_otp(email):
    secret = pyotp.random_base32()
    otp_secrets[email] = secret
    return pyotp.TOTP(secret).now()

def verify_otp(email, otp_code):
    secret = otp_secrets.get(email)
    if not secret:
        return False
    return pyotp.TOTP(secret).verify(otp_code)
