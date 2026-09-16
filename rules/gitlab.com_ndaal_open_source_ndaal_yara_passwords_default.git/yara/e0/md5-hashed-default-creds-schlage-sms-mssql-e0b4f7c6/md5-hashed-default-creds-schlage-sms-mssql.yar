rule md5_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b53c0fdf4273b55461084fc10fe2337"
    $a1="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a2="3b53c0fdf4273b55461084fc10fe2337"
    $a3="7429aa8563e64a38507552aa90fb331f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}