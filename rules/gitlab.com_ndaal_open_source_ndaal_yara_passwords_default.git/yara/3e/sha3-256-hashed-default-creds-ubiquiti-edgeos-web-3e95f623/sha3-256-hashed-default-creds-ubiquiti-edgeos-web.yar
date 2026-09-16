rule sha3_256_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
    $a1="f5ac746ad512d7ad9a394bd8ac3d1a26084ac0c8a64528f6b6fb6a47666378ff"
condition:
    ($a0 and $a1)
}