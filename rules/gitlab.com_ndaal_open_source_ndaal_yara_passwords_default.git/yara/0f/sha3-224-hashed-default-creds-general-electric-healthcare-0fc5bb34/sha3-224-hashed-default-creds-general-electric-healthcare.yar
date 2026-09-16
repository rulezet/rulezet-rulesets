rule sha3_224_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a2="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a5="341ea0cb47201bc88d3e18913f3f62b37543ff530007bd7bf9c71790"
    $a6="a01a8a93f5df478a4bf3b40e234a34011a1c02825ac824aef4db3f27"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="200410e8dc18f24fc10e3a7e87e74d6e54e3a993a797dd4fecaa6b1a"
    $a9="65ebf58d74d771b108ee706f2bc4cf4eb492b07e0e73b7552cf9e61e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}