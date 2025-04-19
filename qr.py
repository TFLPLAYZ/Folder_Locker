import pyotp
import qrcode

# Config
app_name = "FolderLocker"
issuer_name = "SecureLocker"
secret_file = ".totp_secret"

# Generate a new secret
secret = pyotp.random_base32()

# Save the secret to a file
with open(secret_file, "w") as f:
    f.write(secret)

# Create the provisioning URI
uri = pyotp.totp.TOTP(secret).provisioning_uri(name=app_name, issuer_name=issuer_name)

# Generate the QR code
qr = qrcode.make(uri)
qr.show()  # This opens the QR code image in your default image viewer

# Optional: print the URI and secret for manual entry
print(f"TOTP URI (for QR scanning): {uri}")
print(f"TOTP Secret (save this securely): {secret}")
