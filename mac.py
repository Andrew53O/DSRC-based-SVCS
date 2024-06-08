from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hmac
import hashlib

# Generate global RSA keys
key = RSA.generate(2048)
(global_public_key, global_private_key) = key.publickey(), key
print(f"Global Public Key Size: {len(global_public_key.export_key())} bytes")
print(f"Global Private Key Size: {len(global_private_key.export_key())} bytes")

def hash_key(key):
    # Hash the key to generate a MAC key
    return hashlib.sha256(key.export_key()).digest()

def mac_msg(msg, key):
    # Generate a MAC tag for the message
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def sender(msg, receiver_public_key):
    # Generate sender's RSA keys

    key = RSA.generate(2048)
    (sender_public_key, sender_public_key) = key.publickey().export_key(), key.export_key()

    # Generate MAC key and tag
    mac_key = hash_key(global_public_key)
    tag = mac_msg(msg, mac_key)

    # Concatenate message and tag, and encrypt with receiver's public key
    cipher = PKCS1_OAEP.new(receiver_public_key)
    payload = cipher.encrypt(msg.encode('utf-8') + tag)

    # print the length of the payload
    print(f"Payload Size: {len(payload)} bytes")
    return payload

def receiver(payload, receiver_private_key):
    # Decrypt the payload
    cipher = PKCS1_OAEP.new(receiver_private_key)
    decrypted_payload = cipher.decrypt(payload)

    # Split the payload into message and tag
    receiver_msg = decrypted_payload[:-32].decode('utf-8')
    receiver_tag = decrypted_payload[-32:]

    # Generate MAC key and tag
    mac_key = hash_key(global_public_key)
    tag = mac_msg(receiver_msg, mac_key)

    # Verify the tag
    if tag == receiver_tag:
        print("Message is authentic")
        return True
    else:
        print("Message is not authentic")
        return False

# Generate receiver's RSA keys
key = RSA.generate(2048)
(receiver_public_key, receiver_private_key) = key.publickey().export_key(), key.export_key()

# Sender sends a message
payload = sender("Hello", receiver_public_key)

# Receiver receives the message
receiver(payload, receiver_private_key)