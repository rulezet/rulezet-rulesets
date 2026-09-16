rule mysql41_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*0074B56DECC0A1B2EA1AC6BA1C628956B63F211D"
    $a1="*6C71A06D2D6602321F2364B9EE499544DAEB72A8"
    $a2="*0074B56DECC0A1B2EA1AC6BA1C628956B63F211D"
    $a3="*4382B54C09069D7EE06063036FBB4AC5A981A5DE"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}