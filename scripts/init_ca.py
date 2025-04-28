import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

CA_DIR = "ca"

os.makedirs(CA_DIR, exist_ok=True)

# Генерация корневого ключа
root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
root_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA"),
])
root_cert = (
    x509.CertificateBuilder()
    .subject_name(root_subject)
    .issuer_name(root_subject)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(root_key, hashes.SHA256())
)

# Сохраняем корневой ключ
with open(os.path.join(CA_DIR, "root_ca.key"), "wb") as f:
    f.write(root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

# Сохраняем корневой сертификат
with open(os.path.join(CA_DIR, "root_ca.crt"), "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))


# Генерация промежуточного ключа
intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
intermediate_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg Intermediate CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyIntermediateCA"),
])
intermediate_cert = (
    x509.CertificateBuilder()
    .subject_name(intermediate_subject)
    .issuer_name(root_cert.subject)
    .public_key(intermediate_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .sign(root_key, hashes.SHA256())
)

# Сохраняем промежуточный ключ
with open(os.path.join(CA_DIR, "intermediate_ca.key"), "wb") as f:
    f.write(intermediate_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

# Сохраняем промежуточный сертификат
with open(os.path.join(CA_DIR, "intermediate_ca.crt"), "wb") as f:
    f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))

print("✅ Корневой и промежуточный сертификаты успешно созданы!")
