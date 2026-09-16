rule sha3_256_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="59704ae14dd3d4ad331b2e058426998cfb93d921adc38b61f3460d81619e0979"
    $a1="bee935851f51f5e0434b5b7fcd10dfe137ec896f05d0b0c24d84fdba6c228dc7"
condition:
    ($a0 and $a1)
}