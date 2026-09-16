rule sha256_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
    $a1="c6c6dc4efdd314700252330e1e36db2ef1b1cc2d703b884168c541963336a0c8"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a5="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}