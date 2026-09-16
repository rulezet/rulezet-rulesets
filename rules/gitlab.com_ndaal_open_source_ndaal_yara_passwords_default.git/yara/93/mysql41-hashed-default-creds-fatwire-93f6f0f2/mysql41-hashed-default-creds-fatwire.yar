rule mysql41_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8033F727E9F00F62A80E3C290BE0C77EEFE6C6EE"
    $a1="*8033F727E9F00F62A80E3C290BE0C77EEFE6C6EE"
    $a2="*11290C5A9E85E7E03189737B950F484889DFC7F2"
    $a3="*7534BEE17FDD8CD64FED6684247311255C9C9298"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}