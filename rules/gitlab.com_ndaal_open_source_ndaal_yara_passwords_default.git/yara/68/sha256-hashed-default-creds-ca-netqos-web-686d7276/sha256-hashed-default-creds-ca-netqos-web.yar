rule sha256_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af1a411ed6a2fdf0eddd9939082f31132f6bd6b7aa1248e7984c8df1ffd0f783"
    $a1="62af322f1b4c8486c31070e10cff6ff44842bf56069e1b60c8270d43a4aa7cb8"
    $a2="af1a411ed6a2fdf0eddd9939082f31132f6bd6b7aa1248e7984c8df1ffd0f783"
    $a3="8eded4f2ebb9f52f61dde870aa854c8ddb06c51bb7fe8e3c8294c1df689a4b57"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}