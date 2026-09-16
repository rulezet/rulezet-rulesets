rule sha224_hashed_default_creds_mediaportal_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mediaportal_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6789e9f5e992874f3c15108d9ef395487cf53a8a057afa9753aea135"
    $a1="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1)
}