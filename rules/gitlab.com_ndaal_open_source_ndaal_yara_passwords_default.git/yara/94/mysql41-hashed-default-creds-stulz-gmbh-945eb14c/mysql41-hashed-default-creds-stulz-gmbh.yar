rule mysql41_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*920D64A0EC733EAEC81A500DF85435A2A14C9300"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*9FB4864B7BC01AC8F342161C162273C95A7A4331"
    $a3="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a4="*6E1C53BB98F8D1934CC291D48AAFAE8613427BB3"
    $a5="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}