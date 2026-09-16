rule sha3_224_hashed_default_creds_lg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lg."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="539bee0eb02f7fcc0359f1dfd8d61dde46fcb9e6aa0783d1d1f621c8"
    $a5="30f407542b2ee78bef00ae1727f39fce9438e06d0f3bded5469c3dfa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}