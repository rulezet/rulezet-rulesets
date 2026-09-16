rule sha3_512_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0b180290c6f9e27fad41aa16333dce831e0f191e265d2523a5d40327fea05e72e45f3f042b82acf0c54b8ce530465cc94cf6e323a24046b03a28fd25053fa356"
    $a1="0b180290c6f9e27fad41aa16333dce831e0f191e265d2523a5d40327fea05e72e45f3f042b82acf0c54b8ce530465cc94cf6e323a24046b03a28fd25053fa356"
condition:
    ($a0 and $a1)
}