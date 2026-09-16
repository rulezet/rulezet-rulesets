rule sha3_224_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
    $a3="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a4="9f5a4e1fa8c4d03581ec9b4bf4cb25b2a2c97d6303fdc2ec7f3eeeeb"
    $a5="2e5e2f7ca78996bf07462d3586cee50e70e6c09ceb67a6ccce49c378"
    $a6="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
    $a7="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}