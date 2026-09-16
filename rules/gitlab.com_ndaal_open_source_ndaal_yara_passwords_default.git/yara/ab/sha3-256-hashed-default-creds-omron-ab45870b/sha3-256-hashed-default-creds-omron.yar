rule sha3_256_hashed_default_creds_omron
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for omron."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a1="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
condition:
    ($a0 and $a1)
}