rule blake2b_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4f8eb712f1b36d673cd5d67fb6597c3715b4c52bd8a63d9fc0856791379a7fd84deeec04d70c11fcca7e5bdfe950bc74cdf4daffab1c88ef07f129961010146"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="487359a72a4c885d147e60ad6d43d8a738bc7cc6fce1d628df33d8755574ef1e68f8fd2a225fb81697d002bde8e8591c808814baecb8a776efe1827bfcb5c08e"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="de42363405e1e34b996a45cfae3bbb2db5b0e103f1b0cab74641a2f64e64c317a3e67bae59320795741806f482b26202d8e2dab2a02cd2ad7c8cfc0ac5904cf6"
    $a5="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}