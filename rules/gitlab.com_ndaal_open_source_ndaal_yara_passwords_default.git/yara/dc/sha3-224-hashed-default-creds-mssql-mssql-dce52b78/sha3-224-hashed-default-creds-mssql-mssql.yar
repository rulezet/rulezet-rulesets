rule sha3_224_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08212cf33081e27a009858c2af540145b6a4539ce4b2336fd8e8dc25"
    $a1="57299d8b3113c196fa5a93d407903351d730270cb2cbe9aa34958c0b"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a4="96dc79212c6415df2536c4a4ed4905c3b0a25e803cb609375eb0a6ae"
    $a5="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a6="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a7="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a8="55974149b1a5ac08d4b2e027e3e19b9281c808a1d286f22227a4611d"
    $a9="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}