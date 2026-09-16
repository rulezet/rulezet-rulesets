rule blake2b_hashed_default_creds_mysql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="4485295e8d76771c856d20e3ed1167abc172b743fb71b5c23d823c16e51de46f550877b0420444990a3d5b2cae2a13bb141f0484fae5ae0f62190b33acd8198a"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="65aa9e9ce6e9097d5b7056e4d9e57d7efa697a24be1deb0a29b68fcde827c6df578050005433faeb36b9294426e566ca9acece940f726749748e2ad2c945f7ff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}