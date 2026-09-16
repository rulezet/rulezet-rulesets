rule sha3_256_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d593ca80668ff9941bbdce23a382f4482f7a0616dc70f2bc76fda528bbbc69b0"
    $a1="d593ca80668ff9941bbdce23a382f4482f7a0616dc70f2bc76fda528bbbc69b0"
condition:
    ($a0 and $a1)
}