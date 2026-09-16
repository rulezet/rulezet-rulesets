rule sha3_256_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90e6214bbec1ea92e239ac7bc3f41465bf4cf61a166d6c6549947dde4c9d1f48"
    $a1="861da640dfdb2d83d8c0620db7bdb33739fbf910406c2f42bf6b3dca610f37d4"
condition:
    ($a0 and $a1)
}