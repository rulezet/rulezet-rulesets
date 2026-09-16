rule md5_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff104b2dfab9fe8c0676587292a636d3"
    $a1="ff104b2dfab9fe8c0676587292a636d3"
    $a2="084e0343a0486ff05530df6c705c8bb4"
    $a3="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}