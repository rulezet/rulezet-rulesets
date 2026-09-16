rule sha512_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d22a867aea2dcca38246d7458624853195e17c484cfc42c9ce48e385042c27fc17430f6f5f547e168d1e9abc71c02490ddca494ca2d847a921640a4f22bfa075"
    $a1="d22a867aea2dcca38246d7458624853195e17c484cfc42c9ce48e385042c27fc17430f6f5f547e168d1e9abc71c02490ddca494ca2d847a921640a4f22bfa075"
condition:
    ($a0 and $a1)
}