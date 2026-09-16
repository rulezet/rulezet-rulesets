rule sha3_224_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9817fd4e8ae39d6e41532989e4422c5a7e46411dab4d2fdfa2270dad"
    $a1="af537e3fe10bce58cff5834fe36a35fba380497f0065f36aa6b7061e"
condition:
    ($a0 and $a1)
}