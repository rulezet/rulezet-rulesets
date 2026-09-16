rule blake2s_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4148d74dcbfb2aafda9d5de6d28c3dab08c292f4462aaeb18876f6c6eeb6096"
    $a1="1be1829c5c6c832651cc519b9b1063c1a0af837f094ba6423b1bcb62494a4b4a"
condition:
    ($a0 and $a1)
}