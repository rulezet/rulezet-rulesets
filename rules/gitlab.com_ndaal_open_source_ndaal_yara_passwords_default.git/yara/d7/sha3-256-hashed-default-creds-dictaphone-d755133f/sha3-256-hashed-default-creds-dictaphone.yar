rule sha3_256_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a1="2a6a93d8fbdb169f05a0270ae9040e5a68a420f7d8902828031676487665ffac"
    $a2="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
    $a3="b41c4dacb6eea63d2ddcdae18a2bca25429a837c1bafa5037baad8283c1ae514"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}