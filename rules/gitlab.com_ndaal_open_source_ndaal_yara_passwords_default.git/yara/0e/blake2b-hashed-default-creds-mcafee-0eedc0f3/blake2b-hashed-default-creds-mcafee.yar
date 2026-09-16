rule blake2b_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cd3e449a83a12ffc0a38433df2543e4d9f3ed542b7acdecb4ff4fb583e0b7042a64de0a0ed4ad2073f21f6ef28428af312f7000d868e61c9d89ffeff98c03802"
    $a1="8922f20e276ddb97d11d7d216d3ad7ccd72719248b86d3b2b4ba5c4f3bc844a38a3eb45cce63c0ff91bce1aabfb76906d94580646d1d61cd2680b1983094b432"
    $a2="eba34065a1d45b3bfd700926b250ee119b42b331977b43b61f6c9d383fcb8f2d898d2b003253796e0eda3a37d3fdffd131758ad348e94dfe9685f787c7911a42"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="fab4786fde9be856f41cb7cabbd693ce8cfc97b2882ff984c205e9318756e6f9531cacf668cb87ad07cea095c2234a58bb3acb66635a9f2175d5ebd4001b1cc1"
    $a5="428c6644774fcd5578947a823c51c5fe21353d9885587811f35d262bc4628e37850d3fe0e52345b7f41d512877be1e95ba20d17e63f84c2fab5dd6261bbb7ff2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}