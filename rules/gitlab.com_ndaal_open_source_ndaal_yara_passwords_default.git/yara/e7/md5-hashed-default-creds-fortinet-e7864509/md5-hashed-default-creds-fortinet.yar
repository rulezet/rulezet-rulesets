rule md5_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="9ae55575a3588889a4609a010ef6767e"
    $a2="cf040822a8397a3c85035902db18b7ca"
    $a3="9ae55575a3588889a4609a010ef6767e"
    $a4="a89e1931f7b4c706e14b87c641e4fcfb"
    $a5="9ae55575a3588889a4609a010ef6767e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}