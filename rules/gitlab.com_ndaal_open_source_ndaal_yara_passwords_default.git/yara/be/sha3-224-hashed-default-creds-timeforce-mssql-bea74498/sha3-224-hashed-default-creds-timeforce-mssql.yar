rule sha3_224_hashed_default_creds_timeforce_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for timeforce_mssql."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef06e82c8a4c7e135415a80db3a1a0f5bc1ca6efabd2fbb5fd8baa80"
    $a1="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a2="53afe56b4e3c62eb3f51ce6bf701e92176417152f3c81fc8a60104c5"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}