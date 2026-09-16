rule sha3_224_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
    $a1="26eb9af91717ecfc0c09d6931b38d5cc042c100dd0f953a6dbe46858"
condition:
    ($a0 and $a1)
}