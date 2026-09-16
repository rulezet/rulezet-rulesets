rule sha3_224_hashed_default_creds_raspberry_pi_foundation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_foundation."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc95a37066e9fff8910dc7f143bca7d4841f68f2c0d82199faddf329"
    $a1="a481172d9b06124e8ae43cee7d7adbb406cad55a7501f4de91c20327"
condition:
    ($a0 and $a1)
}