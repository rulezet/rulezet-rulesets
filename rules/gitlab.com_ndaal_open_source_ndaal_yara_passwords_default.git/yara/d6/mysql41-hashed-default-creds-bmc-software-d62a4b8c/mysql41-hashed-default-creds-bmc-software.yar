rule mysql41_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*764E1C424B39A89E323850F81D24B04913D2183F"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*D256D6EE5B50C3BA278EEA56D8588AA955C9B3D9"
    $a3="*BC61FCB41C452B98E593489C541F6BFF28FF570D"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}