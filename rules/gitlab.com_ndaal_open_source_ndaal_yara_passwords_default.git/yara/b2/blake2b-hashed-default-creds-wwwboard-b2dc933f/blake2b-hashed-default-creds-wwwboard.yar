rule blake2b_hashed_default_creds_wwwboard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wwwboard."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00ffdd5905eb7c82c8d461b003b7e441a2d36047ba152b71e4c7e4fd505b77c6399478e66a6e9571c040403a5913678e67ccd826d9552ceb5e743b60be6971ba"
    $a1="4ad550e8678f077e4b1e428b78898797f8170e8c08d5bbc7b56c96418ffbc127b3dadff9a96eaaaa3bdad17979a007f32880c9132118570edc2832853cd3f1a3"
condition:
    ($a0 and $a1)
}