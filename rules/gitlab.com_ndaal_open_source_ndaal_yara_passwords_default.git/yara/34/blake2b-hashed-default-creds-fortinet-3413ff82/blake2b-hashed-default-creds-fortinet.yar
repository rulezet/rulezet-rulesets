rule blake2b_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
    $a2="ca89b9e8c8767136c363639e87f2d7d61bf34bf69a07fd973b154891026f51eaa4aa4f1efda5e217f1a78334b093f58d980074163c4868a07d1a99ab240a24bc"
    $a3="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
    $a4="3461b3ddae3e29468d925f1ec18d41671f1237914a0642ec559cec10fb42918b444d54ed9fcd97fe49b3652143349af8c00aeb6b5520163c83db949e9d2b47af"
    $a5="4cb279237ab023accfa7e593fa8bdf959ee5faa525dd346e24f88e7115e11fbb688bc98d52ae9beb8ac30c23af8ca04abc3c390271ab8f8fbe9f431fdaa7b483"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}