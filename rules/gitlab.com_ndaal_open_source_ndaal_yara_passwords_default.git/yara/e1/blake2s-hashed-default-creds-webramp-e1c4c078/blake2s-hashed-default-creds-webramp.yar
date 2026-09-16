rule blake2s_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7680e87465419fa65154da45a68730cf3e8ff5f078c8d3805558d872669bd886"
    $a1="1be1829c5c6c832651cc519b9b1063c1a0af837f094ba6423b1bcb62494a4b4a"
    $a2="a4148d74dcbfb2aafda9d5de6d28c3dab08c292f4462aaeb18876f6c6eeb6096"
    $a3="1be1829c5c6c832651cc519b9b1063c1a0af837f094ba6423b1bcb62494a4b4a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}