rule blake2b_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57178a4a67c7974d512a81ca798eb89e5a100edd27ab0422c690d527f15c31f6b0046a89173b65409ad3fb6fb62ede7c26deafa34895e889927fec29b46efbcd"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="d3a9a8c875ab459b9de48c34114330a6f228d525fca03b00eccd95f6ed9f9f18ee71b61bed14503ba8d0a8f52d8fda17cb3cf7a3da20589a2d7ce8d17a943da0"
    $a3="d3a9a8c875ab459b9de48c34114330a6f228d525fca03b00eccd95f6ed9f9f18ee71b61bed14503ba8d0a8f52d8fda17cb3cf7a3da20589a2d7ce8d17a943da0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}