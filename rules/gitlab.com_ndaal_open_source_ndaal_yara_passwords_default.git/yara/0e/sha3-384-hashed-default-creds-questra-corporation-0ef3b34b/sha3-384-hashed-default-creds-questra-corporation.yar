rule sha3_384_hashed_default_creds_questra_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for questra_corporation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a1="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a2="96981e29e9d6a720508bd994a4b2c99391d41edab24c0355c5af01edd6af29b2c16e091e14450d82a5123e555e610df8"
    $a3="96981e29e9d6a720508bd994a4b2c99391d41edab24c0355c5af01edd6af29b2c16e091e14450d82a5123e555e610df8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}