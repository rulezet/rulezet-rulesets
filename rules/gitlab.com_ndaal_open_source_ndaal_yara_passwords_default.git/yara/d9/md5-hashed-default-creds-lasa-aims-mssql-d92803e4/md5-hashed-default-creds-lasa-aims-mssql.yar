rule md5_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b40239058b41256ebe4580de6a26901d"
    $a1="73acd9a5972130b75066c82595a1fae3"
    $a2="b40239058b41256ebe4580de6a26901d"
    $a3="30781f1fc2f9342ceb1ad2f6f35a51db"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}