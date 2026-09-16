rule sha224_hashed_default_creds_firebird_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird_project."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a5fcaa8156df5fc8f006e239b44d01fd54862cee3056ef9ece150db"
    $a1="8b13d1565c9e9c0b74899415243e152d8caadf0f714b1f1f630fca2f"
condition:
    ($a0 and $a1)
}