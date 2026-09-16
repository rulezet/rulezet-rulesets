rule blake2b_hashed_default_creds_corecess
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for corecess."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2c9ac417babdca03ccdf3bdb2df43c7f565f19db79df7031f44206a8cd086c71c72871521dfa895bf4e8127e05ae5f09e98f472a2dbf37417df4252a00327730"
    $a1="2c9ac417babdca03ccdf3bdb2df43c7f565f19db79df7031f44206a8cd086c71c72871521dfa895bf4e8127e05ae5f09e98f472a2dbf37417df4252a00327730"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}