rule mysql323_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a4dc7be150b77d5"
    $a1="4d46f05e5baa03d5"
    $a2="1ce6aa8c3a20a717"
    $a3="35f8bd6c396f7c77"
    $a4="0e7537c1022753eb"
    $a5="1c80e4611ba0478b"
    $a6="68a080f411073ecd"
    $a7="6c167e1450501d2d"
    $a8="27cf6f0e66c2e4d9"
    $a9="48a4b1ee0cafb619"
    $a10="56ddd5e8033d53c9"
    $a11="0aaafe081827a729"
    $a12="7bad6fd2567a1ee1"
    $a13="454fe43249c4c821"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}