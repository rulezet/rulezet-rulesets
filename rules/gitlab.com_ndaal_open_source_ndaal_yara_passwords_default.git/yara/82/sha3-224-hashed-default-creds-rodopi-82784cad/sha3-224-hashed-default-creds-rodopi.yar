rule sha3_224_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cfdba0f58bb5a719fd4f11e003d4526933495cb2cec499af55a0bbb"
    $a1="6cfdba0f58bb5a719fd4f11e003d4526933495cb2cec499af55a0bbb"
    $a2="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
    $a3="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}