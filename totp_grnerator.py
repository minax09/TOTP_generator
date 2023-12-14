import hmac
import hashlib
import struct
import base64
import time

def generate_totp(secret, time_step=30, t0=0, digits=6):
    # Get the current time in seconds
    current_time = int(time.time())

    # Calculate the counter value
    counter = (current_time - t0) // time_step

    # Convert the counter to bytes using big-endian encoding
    counter_bytes = struct.pack('>Q', counter)

    # Convert the secret to bytes
    secret_bytes = bytes(secret, 'utf-8')

    # Generate the HMAC-SHA-512 hash
    hash_digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha512).digest()

    # Get the offset from the last nibble of the hash_digest
    offset = hash_digest[-1] & 0x0F

    # Take 4 bytes from the hash_digest starting from the offset
    truncated_hash = hash_digest[offset:offset + 4]

    # Convert the truncated hash to an integer
    otp_value = struct.unpack('>I', truncated_hash)[0] & 0x7FFFFFFF

    # Apply the modulo operation to get a 6-digit number
    otp_value %= 10 ** digits

    # Format the OTP value with leading zeros if needed
    otp = '{:0{width}}'.format(otp_value, width=digits)

    return otp

email = "nahalamina25@gmail.com"
token_shared_secret = email + "HENNGECHALLENGE003"

totp = generate_totp(token_shared_secret)
print("TOTP:", totp)
