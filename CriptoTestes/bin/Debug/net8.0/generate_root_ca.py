from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
import datetime

# Função para gerar o certificado Root CA
def generate_root_ca():
    # Parâmetros do certificado
    country_name = "BR"
    state_or_province_name = "RS"
    locality_name = "Porto Alegre"
    organization_name = "LevelCode"
    organizational_unit_name = "LevelCode"
    common_name = "LevelCode"
    email_address = "lucasfkaral@gmail.com"
    
    # Geração da chave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Construção do Nome Distinto (Subject e Issuer)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
    ])

    # Geração do certificado
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Certificado válido por 20 anos
        datetime.datetime.utcnow() + datetime.timedelta(days=365 * 20)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(private_key, hashes.SHA256())

    # Exportar a chave privada e o certificado para arquivos
    with open("RootCA.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("RootCA.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("Certificado Root CA gerado com sucesso.")

# Executar a função
generate_root_ca()
