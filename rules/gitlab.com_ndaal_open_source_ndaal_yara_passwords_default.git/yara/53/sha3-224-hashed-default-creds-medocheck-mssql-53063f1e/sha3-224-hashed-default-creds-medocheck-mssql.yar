rule sha3_224_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a26d79123e7ad8851c6dd154000166ea9b5fe2f3093aaed0f6e3530"
    $a1="823cd505006e0cc9e255635f48e3f3c7d6d763363078d714f5feff1e"
condition:
    ($a0 and $a1)
}