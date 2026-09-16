rule sha3_224_hashed_default_creds_samsung
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samsung."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="041e2404db640aa4790a12014155151943dd03976641750848be1d5f"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="fce6b65ff1f6bdf9a6f0aacd5e7a9dc7644d73363d611da652b343ef"
    $a3="fce6b65ff1f6bdf9a6f0aacd5e7a9dc7644d73363d611da652b343ef"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="d2cd5fa6b8c8eeb68f7fef639fd4123a02843f3e26e9aebc947f58f3"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}