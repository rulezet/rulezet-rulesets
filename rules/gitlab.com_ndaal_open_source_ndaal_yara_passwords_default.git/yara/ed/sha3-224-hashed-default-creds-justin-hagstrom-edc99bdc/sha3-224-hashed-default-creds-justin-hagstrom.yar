rule sha3_224_hashed_default_creds_justin_hagstrom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for justin_hagstrom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
    $a3="3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}