rule sha3_224_hashed_default_creds_greatspeed
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for greatspeed."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb6d80bd85e45f831eddfcaa688b7e21a8ab8a25590da3473fb7f80a"
    $a1="191a452050220815ecf53b385b21927c7ce4987503c003f50370d499"
    $a2="f627ae1d9365ec55d05c8a1e2f2e45b5818dfe9bdec1001cc2f6e6ae"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}