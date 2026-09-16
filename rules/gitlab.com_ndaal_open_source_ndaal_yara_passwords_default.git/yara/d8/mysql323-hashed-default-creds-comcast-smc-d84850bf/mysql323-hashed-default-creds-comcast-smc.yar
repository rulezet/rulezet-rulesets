rule mysql323_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3975b65f400d2d36"
    $a1="31563c0a19953d16"
    $a2="6c986ac36a448ba5"
    $a3="31563c0a19953d16"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}