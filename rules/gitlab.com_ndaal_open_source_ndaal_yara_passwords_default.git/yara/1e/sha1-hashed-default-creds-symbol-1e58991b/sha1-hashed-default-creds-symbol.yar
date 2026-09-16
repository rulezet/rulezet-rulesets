rule sha1_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="810a25d76c31e495cc070bdf42e076f7c9b0a1cd"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="3f84ef531f9db996694ad09a8fdddbca1440577e"
    $a3="3f84ef531f9db996694ad09a8fdddbca1440577e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}