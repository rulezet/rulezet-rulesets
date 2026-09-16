rule sha3_224_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5096587e73490a4f32ec1e62a8e14c062fb6c0303a0fc6f4b0e06a7b"
    $a1="5096587e73490a4f32ec1e62a8e14c062fb6c0303a0fc6f4b0e06a7b"
    $a2="39ddca3b2c0fec73ee24155debf4c729c0a1631232fc26fc71b5bb45"
    $a3="248350fc49c1493ada8146d0f415f8f6f4c6ccb7562e420946547f86"
    $a4="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a5="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a6="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
    $a7="99e9dfd41c89f21695b6117deb842ac61e71f2a2e2ee4e248d7ed54f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}