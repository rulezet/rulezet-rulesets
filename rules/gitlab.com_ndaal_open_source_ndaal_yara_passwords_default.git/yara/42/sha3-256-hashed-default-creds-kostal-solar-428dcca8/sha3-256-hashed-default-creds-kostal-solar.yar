rule sha3_256_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="850e92e0092a7b5ed8dca9a782d4fa027141dedd938d466527eea2f0c0c3bcc1"
    $a1="bb9ece380b6d7ce363f6a83281dfbcce44e2bd152d0a4a53b630960ec200d2fe"
condition:
    ($a0 and $a1)
}