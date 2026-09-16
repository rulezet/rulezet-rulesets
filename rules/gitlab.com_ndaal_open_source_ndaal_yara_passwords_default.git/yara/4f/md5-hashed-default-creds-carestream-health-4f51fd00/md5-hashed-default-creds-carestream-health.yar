rule md5_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2d8bb4924f59b71c06960e07bfca3fa"
    $a1="6dff64efaf963fbf93dacefdf33986db"
    $a2="b2d8bb4924f59b71c06960e07bfca3fa"
    $a3="67795e98229f004a42d43d5ce62d007e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}