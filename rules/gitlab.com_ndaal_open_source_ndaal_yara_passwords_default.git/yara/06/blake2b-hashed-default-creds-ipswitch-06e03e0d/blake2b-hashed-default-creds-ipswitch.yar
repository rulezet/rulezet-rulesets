rule blake2b_hashed_default_creds_ipswitch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ipswitch."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="19da19607dd7f25aa7f3a718f0926dfbe036603f89af6a4f517b67986d805bdddbc7e79ecba4193e27aea7163213e71503ea92ae250fa3119a63e0c319e1bfcd"
    $a3="be54fff1723d905f9b44a322967fd381de9e3a173d7d65f2f2bdcfae739b471ac333d54b2749a31e68d1483b5f06d66d4057e1f225cdcbc6d4606dc3c888b0b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}