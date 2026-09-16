rule sha3_224_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="0509e9a858996f62da0f676687a1e2b209ed07819cd43f3021981b38"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="0509e9a858996f62da0f676687a1e2b209ed07819cd43f3021981b38"
    $a4="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a5="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}