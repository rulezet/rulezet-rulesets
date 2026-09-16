rule mysql41_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a1="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a2="*A9036AB3C885F8768D534E1666C52AF87780187F"
    $a3="*A9036AB3C885F8768D534E1666C52AF87780187F"
    $a4="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a5="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}