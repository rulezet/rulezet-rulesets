rule sha3_384_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ef3678ad01ee027a5142d36fa4b27bfb2650f7b3e3bf7e508fb180f661468bcfaae8b545ac197c2ba0921dc005d39f19"
    $a1="93e239479ca32eb330eddf7beb6103d71beac60a0ac7b3a7ffb179ad88c83a6f6132672ad5ffa860191c278f49fe65f9"
condition:
    ($a0 and $a1)
}