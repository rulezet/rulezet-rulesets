rule sha3_512_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13660c9bcdee30264a732cd1939515a21f5680ddb651af51b6bdfffd342d5b38ce6638e914ae3191e8eadf5566974a052ef79b57fdacede1eb691cacde5ada1d"
    $a1="62c809d154aaffd4d15327c159a3f4c319f6617aea1386a9027dd84289d59faac47e61d22d0a76139b7b558c6ba344d2143a906d930076ca63162183a97c7f83"
condition:
    ($a0 and $a1)
}