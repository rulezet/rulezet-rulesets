rule mysql41_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*BB969FB9227CD4FE499D32CCB9E71CCA72DF9205"
    $a1="*AD338CCE95A3E1687E9D1D35E2A8C166D8B43AC0"
    $a2="*3ED66159C522973010C1A3D744A6B06FB9BE47B7"
    $a3="*BE353D0D7826681F8B7C136ED9824915F5B99E7D"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}