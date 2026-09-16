rule blake2b_hashed_default_creds_barracuda
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="0a0d2314ae1ea3e14d08e1eb75ef0157a9e15b006180f53d590cf22336835c886b250604275c7a5c522e9065f9de58510554875aba7625c01a16162a22ded7e9"
    $a3="0a0d2314ae1ea3e14d08e1eb75ef0157a9e15b006180f53d590cf22336835c886b250604275c7a5c522e9065f9de58510554875aba7625c01a16162a22ded7e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}