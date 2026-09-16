rule sha512_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06ff6f2da1670621005ace3ef9362dee318b9a3c9d30ea160b3ace253519693bcf9fc9c25c5d57b4b73dc8f5ff305f7ed121c2155ba8591bd90fad6bde2398ca"
    $a1="fcae92a850cd17f5921a42d325736beffab3cb664ba04319d7ab4a4f2eb43efd4c5be41e5323e3d86180eb33b807e0e07c21a3e98beb7ced33e1d531fc06e704"
condition:
    ($a0 and $a1)
}