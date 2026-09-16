rule sha224_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="fc086c0abf2fafed4860c0b5be9073b05b3600c58003518f3bc3ae67"
    $a2="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a3="008153f5be901efbcd07b51fc97c16c126deff115c63e94aa54f207c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}