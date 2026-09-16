rule md5_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a0f848942ce863cf53c0fa6cc684007d"
    $a1="a0f848942ce863cf53c0fa6cc684007d"
    $a2="9ce21d8f3992d89a325aa9dcf520a591"
    $a3="96f9963e25520a9011c82401920794f0"
    $a4="a32c3d3cec20f5a09595b857e45b477f"
    $a5="96f9963e25520a9011c82401920794f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}