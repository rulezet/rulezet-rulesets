rule sha3_256_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="890da150f32d2db6fc8f1254b1671cec94e3114a453cb98ef67ec942ee744367"
    $a1="03789d1aa662b7e4e363b211f026f6d840912607b7ccdbb5210322d378ce1f4d"
condition:
    ($a0 and $a1)
}