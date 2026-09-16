rule md5_hashed_default_creds_firebird_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird_project."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abe6db4c9f5484fae8d79f2e868a673c"
    $a1="4811df2c83bee7ee3a883640cc4d80af"
condition:
    ($a0 and $a1)
}