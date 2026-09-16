rule sha3_256_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5879f5e2e502c1c5ef36ef1cff4080bc4d02666957678e294930ff2d00d119d0"
    $a1="5879f5e2e502c1c5ef36ef1cff4080bc4d02666957678e294930ff2d00d119d0"
condition:
    ($a0 and $a1)
}