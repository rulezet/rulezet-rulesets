rule blake2b_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22b0dae0bc77d7551a5422bfe873dac6a40ecd29b1681b661a31ac42a2009809327c80e4c9e1cea735858a744450835dca72a02353857b9a1f008e03253c0dae"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
    $a3="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}