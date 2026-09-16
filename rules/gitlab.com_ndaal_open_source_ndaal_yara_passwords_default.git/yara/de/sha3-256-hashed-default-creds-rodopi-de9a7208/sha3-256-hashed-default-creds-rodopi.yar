rule sha3_256_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cd025ec6ff48b39df1dcbdbc866d9fceec8b5db3fdfadf046e56d7e44a3bb23"
    $a1="5cd025ec6ff48b39df1dcbdbc866d9fceec8b5db3fdfadf046e56d7e44a3bb23"
    $a2="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
    $a3="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}