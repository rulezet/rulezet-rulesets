rule sha3_224_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a3="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
    $a4="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
    $a5="d263b1a42751fec04f7d158f17d618e58e278ecf7ada3dc66c3e097c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}