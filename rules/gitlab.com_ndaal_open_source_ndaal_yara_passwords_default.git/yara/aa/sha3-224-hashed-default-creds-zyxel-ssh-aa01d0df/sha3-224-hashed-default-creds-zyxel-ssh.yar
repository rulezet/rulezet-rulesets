rule sha3_224_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5941b2b71710b18d8edfdd60680bb91a4ec86d5b8977798debcce383"
    $a1="f34188f6d2656d5b004f971527c55270dadc7a5d1132d28a5621181a"
condition:
    ($a0 and $a1)
}