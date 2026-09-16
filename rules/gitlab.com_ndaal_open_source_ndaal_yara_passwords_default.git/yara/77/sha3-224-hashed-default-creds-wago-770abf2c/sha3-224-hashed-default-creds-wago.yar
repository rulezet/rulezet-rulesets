rule sha3_224_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84f66ede6f06ada7b0210161cf5cc5bf6819cfc650da89c600c1504a"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a3="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a4="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="ba36e4d79433494c312fb57ae2629cd1522c5eba0a2b22a4af9fe17e"
    $a7="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a8="343db195dd3f58024a57b75e6dc551036b92f9f026100e263530dcab"
    $a9="75f58bac7357eb7212974978e36e03df8be67637b1dc24ef0ece0414"
    $a10="84f66ede6f06ada7b0210161cf5cc5bf6819cfc650da89c600c1504a"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}