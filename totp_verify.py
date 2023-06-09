import hmac
import hashlib
import struct
import time

# Function to generate the TOTP code
def generate_totp(secret_key):
    # Get the current Unix timestamp
    current_time = int(time.time())

    # Interval duration (RFC 6238 recommends 30 seconds)
    interval_duration = 30

    # Calculate the counter value based on the current time and interval duration
    counter = current_time // interval_duration

    # Convert the counter value to a byte array
    counter_bytes = struct.pack(">Q", counter)

    # Generate an HMAC-SHA1 hash using the secret key and the counter value
    hmac_result = hmac.new(secret_key, counter_bytes, hashlib.sha512).digest()

    # Get the offset value from the last 4 bits of the hash
    offset = hmac_result[-1] & 0x0F

    # Extract 4 bytes starting from the offset to get the dynamic binary code
    dynamic_binary_code = hmac_result[offset:offset+4]

    # Convert the dynamic binary code to an integer
    dynamic_code = struct.unpack(">I", dynamic_binary_code)[0]

    # Apply a modulo operation to get the TOTP value in the desired range
    totp_value = dynamic_code % (10 ** 10)

    # Format the TOTP value as a 6-digit code with leading zeros if necessary
    totp_code = "{:10d}".format(totp_value)

    return totp_code


# Function to authenticate the provided TOTP code
def authenticate_totp(secret_key, user_totp):
    # Get the current Unix timestamp
    current_time = int(time.time())

    # Interval duration (RFC 6238 recommends 30 seconds)
    interval_duration = 30

    # Calculate the counter value based on the current time and interval duration
    counter = current_time // interval_duration

    # Convert the counter value to a byte array
    counter_bytes = struct.pack(">Q", counter)

    # Generate an HMAC-SHA1 hash using the secret key and the counter value
    hmac_result = hmac.new(secret_key, counter_bytes, hashlib.sha512).digest()

    # Get the offset value from the last 4 bits of the hash
    offset = hmac_result[-1] & 0x0F

    # Extract 4 bytes starting from the offset to get the dynamic binary code
    dynamic_binary_code = hmac_result[offset:offset+4]

    # Convert the dynamic binary code to an integer
    dynamic_code = struct.unpack(">I", dynamic_binary_code)[0]

    # Apply a modulo operation to get the TOTP value in the desired range
    totp_value = dynamic_code % (10 ** 10)

    # Format the TOTP value as a 6-digit code with leading zeros if necessary
    expected_totp = "{:10d}".format(totp_value)

    # Compare the expected TOTP code with the user-provided TOTP code
    if expected_totp == user_totp:
        return True
    else:
        return False


# Replace "SHARED_SECRET" with your actual shared secret key
shared_secret = b"SHARED_SECRET"

# Generate the current TOTP code
print(generate_totp(shared_secret))

# Prompt the user to enter the TOTP code
user_totp = input("Enter the TOTP code: ")

# Authenticate the provided TOTP code
is_valid = authenticate_totp(shared_secret, user_totp)

# Print the authentication result
if is_valid:
    print("Authentication successful!")
else:
    print("Authentication failed!")
