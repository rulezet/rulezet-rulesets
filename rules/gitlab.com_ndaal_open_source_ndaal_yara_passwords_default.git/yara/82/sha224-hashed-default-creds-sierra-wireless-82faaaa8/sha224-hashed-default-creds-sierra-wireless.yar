rule sha224_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a1="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a2="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a3="2c39f00d1fce0dfbbf1ba285130e1a35b299424ab5728c9f12ababbf"
    $a4="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a5="7a8cff2f745efa1dd50e5be48bd5440a9ccfac498c1058391abab0cb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}