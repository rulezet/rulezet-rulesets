rule sha3_224_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdc3538a5add6a1cf4d6165a3ea3b55064d86cdc6926f7c123a5d4a5"
    $a1="a382bff6b567a7d78da1a0ee0e814ed13f7d379291fc3081f222a54a"
    $a2="2a3c9c7a3b25e301b7055c67e9067a7bf61a0c0518ff0ad9178b940c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="b101af0364bd8c361bf64048a7028aa22112295fb15dfe84abf74460"
    $a5="617a032c5ce25f836f52ecc48c63e70ed6e5f8cf0aed405ea8354007"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}