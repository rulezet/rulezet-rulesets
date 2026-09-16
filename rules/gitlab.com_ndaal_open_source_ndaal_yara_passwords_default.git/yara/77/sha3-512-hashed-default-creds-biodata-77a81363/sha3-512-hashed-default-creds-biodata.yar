rule sha3_512_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="751d604e4af4e401161f72a9f456c8fadc9147a7cd2fd03a8f337ea7c37141c51e5a601f932993ca739b61733317a531986054ee5adcc715054ca954347cf6a0"
    $a1="ed8d212a4425108e64febf6fc56df6894eb6f8dd283f4adf5382de2c6193e3a02ef3c2c32852adb30fef787d66570369c909a651b2f4771f97238a14d49d562b"
condition:
    ($a0 and $a1)
}