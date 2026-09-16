rule sha3_256_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
    $a1="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
    $a2="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}