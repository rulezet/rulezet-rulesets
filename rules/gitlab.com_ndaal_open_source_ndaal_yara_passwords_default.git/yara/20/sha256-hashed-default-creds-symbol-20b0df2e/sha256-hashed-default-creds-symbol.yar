rule sha256_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b76a7ca153c24671658335bbd08946350ffc621fa1c516e7123095d4ffd5c581"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ba0e4afa93400b805dfcc4b9e6aef549269946e2d1af5ababfc3a73c67912d89"
    $a3="ba0e4afa93400b805dfcc4b9e6aef549269946e2d1af5ababfc3a73c67912d89"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}