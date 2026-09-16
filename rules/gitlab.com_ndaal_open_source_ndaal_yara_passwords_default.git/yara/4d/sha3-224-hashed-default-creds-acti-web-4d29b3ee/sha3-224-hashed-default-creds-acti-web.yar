rule sha3_224_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a3="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a4="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a7="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}