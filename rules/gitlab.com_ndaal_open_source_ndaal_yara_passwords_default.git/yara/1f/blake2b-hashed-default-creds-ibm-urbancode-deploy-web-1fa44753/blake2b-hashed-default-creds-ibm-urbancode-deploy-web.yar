rule blake2b_hashed_default_creds_ibm_urbancode_deploy_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_urbancode_deploy_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="9b2410d3efe52e1470b787790939af5c05988339c9ffaa4a5f9af91e714cb970264c6879fc6300b2e0ac0de7c2fe416d687a614f9bd4db5ce391f55c73d3b7e6"
    $a3="9b2410d3efe52e1470b787790939af5c05988339c9ffaa4a5f9af91e714cb970264c6879fc6300b2e0ac0de7c2fe416d687a614f9bd4db5ce391f55c73d3b7e6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}