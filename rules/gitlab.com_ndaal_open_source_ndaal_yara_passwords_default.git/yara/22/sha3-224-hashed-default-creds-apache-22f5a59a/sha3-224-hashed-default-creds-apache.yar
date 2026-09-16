rule sha3_224_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d8e7588707fba48daee7d5c84183abba58d4f50c6e15088642f010f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a7="3de8fdca6bf5a52ee0ab0c0245531ffae08c7d3e758cec41cd919cac"
    $a8="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a9="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a10="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a11="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a12="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a13="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a14="ed42fc69ab147f031e6e8dd087c0a6fcb5b85a09629d74d265759807"
    $a15="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a16="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a17="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a18="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a19="ad46837af4f88a6dac6ebe92cd110b90db1f097a90408c319d4f29e0"
    $a20="9d8cbed9a6bb66e170ef71639d4d29778a0ee1fb7155e648b9b4954c"
    $a21="6d83e0f1cd0affb9f25b7e774dae50debaddaf4fdaaf34ad317a0b3b"
    $a22="31565b1d31eafd54b573745efeae3b76f95ada17305cb7e21d0c2450"
    $a23="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}