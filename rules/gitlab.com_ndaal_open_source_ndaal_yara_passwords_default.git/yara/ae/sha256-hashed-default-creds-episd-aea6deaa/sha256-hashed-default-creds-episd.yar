rule sha256_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a1a14ff4aab4f1d3efbe2f3fe8e32ec686289ba95e5b2fc3e1f38052d64da522"
    $a1="aa97302150fce811425cd84537028a5afbe37e3f1362ad45a51d467e17afdc9c"
condition:
    ($a0 and $a1)
}