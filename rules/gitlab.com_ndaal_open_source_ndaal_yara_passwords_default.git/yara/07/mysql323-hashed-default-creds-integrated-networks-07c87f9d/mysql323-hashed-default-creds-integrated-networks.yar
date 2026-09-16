rule mysql323_hashed_default_creds_integrated_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for integrated_networks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="446a12100c856ce9"
    $a1="58f7ee435f925abe"
    $a2="4448dd9a39ab97e1"
    $a3="58f7ee435f925abe"
    $a4="738cd1b710afd8d0"
    $a5="58f7ee435f925abe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}