rule sha3_512_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d24a623e3a5f0a3a91824440f820aac11d3c3b4239c9b13ec56c2c6e38307e12a5f48f5e4874e035f75aeb9675be59f82ec6fcd3f4b99a6d33e44c6f2552f41"
    $a1="5fe8998f0f2e111473bdc80a4517dfbb78e8be4f9d7f06cf0a13185827572d36fa358fd4f48d1a47f5688aa8eae076f32b3386d13d592cfe6d64f3410959a10f"
condition:
    ($a0 and $a1)
}