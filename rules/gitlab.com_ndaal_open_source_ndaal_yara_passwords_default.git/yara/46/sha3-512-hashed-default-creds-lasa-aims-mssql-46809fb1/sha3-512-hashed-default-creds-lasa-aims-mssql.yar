rule sha3_512_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42b63c14492e96ea56e4ddff3c8789b6c9fb1c6020370a20806b639a7a4aab1be4deca84f71398ab7534d404120d768163e5e71913dc7ca7e12e55081fcbcb93"
    $a1="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
    $a2="42b63c14492e96ea56e4ddff3c8789b6c9fb1c6020370a20806b639a7a4aab1be4deca84f71398ab7534d404120d768163e5e71913dc7ca7e12e55081fcbcb93"
    $a3="857ab6b10cd5dd98fb7aa7487a835517cddd0355951eb5357bdeef1dee81097f5bfb6bbb9063565c7952111f01f3a114ed564f249d4902a9130ebabc710c6731"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}