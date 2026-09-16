rule md5_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e60bc642fefc11b43792e8745df6c1d"
    $a1="7e60bc642fefc11b43792e8745df6c1d"
    $a2="7e60bc642fefc11b43792e8745df6c1d"
    $a3="913f9c49dcb544e2087cee284f4a00b7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}