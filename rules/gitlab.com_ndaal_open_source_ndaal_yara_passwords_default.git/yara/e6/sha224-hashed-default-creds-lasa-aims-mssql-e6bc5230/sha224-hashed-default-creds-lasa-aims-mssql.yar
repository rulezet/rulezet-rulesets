rule sha224_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04797b6853310ab91c3de92127616fd4fa975f611a5ee2a6a09f3736"
    $a1="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
    $a2="04797b6853310ab91c3de92127616fd4fa975f611a5ee2a6a09f3736"
    $a3="c4fb75c197e41d86d69bb807cd1b3725b5c80f6be6d8304efb1dd50a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}