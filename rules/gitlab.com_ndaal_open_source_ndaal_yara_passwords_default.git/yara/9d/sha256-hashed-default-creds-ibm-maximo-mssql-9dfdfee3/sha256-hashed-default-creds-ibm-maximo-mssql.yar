rule sha256_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a11bf1f3c7c86c71f1b756db5d660aa162636bec4bbd9225e7d47dcf8929d7f7"
    $a1="a11bf1f3c7c86c71f1b756db5d660aa162636bec4bbd9225e7d47dcf8929d7f7"
    $a2="9ad40ad5ebbb4ee39a4fcc4ca4814346072a42210529f279a7f8458aac6d51ed"
    $a3="9ad40ad5ebbb4ee39a4fcc4ca4814346072a42210529f279a7f8458aac6d51ed"
    $a4="bf352bf9f21cefd23afea884311d92a7f1c3d33039615f58e90e273937f31c8a"
    $a5="bf352bf9f21cefd23afea884311d92a7f1c3d33039615f58e90e273937f31c8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}