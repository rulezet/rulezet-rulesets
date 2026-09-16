rule sha3_224_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c47c3b65f4d1014d4a7012696551a53ff1c154fb3025c5b221c56ef0"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="5fd8a9cdd1b01180a7f27844af85a615ed6f9287bd8754a9fabdc8a7"
    $a3="5fd8a9cdd1b01180a7f27844af85a615ed6f9287bd8754a9fabdc8a7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}