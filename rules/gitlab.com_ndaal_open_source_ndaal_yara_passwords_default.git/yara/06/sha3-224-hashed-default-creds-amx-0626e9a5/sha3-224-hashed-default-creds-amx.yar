rule sha3_224_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ec975035b74d3a52a2e13b59981bedfa0b0f39b2fe72401e087c23e"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a4="dd5b22874e0ec4cf5dd62ca0e3f2bbad52ef87202f1a55c56aca8dc4"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a7="1d0dcd2309aa0d40106415568791bac15615139338aa8781d2668d00"
    $a8="4ec975035b74d3a52a2e13b59981bedfa0b0f39b2fe72401e087c23e"
    $a9="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a10="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a11="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a12="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a13="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a14="a65c27ca3b0fd0b303dfd926fba3008533eb4b029581f4d5a8effb67"
    $a15="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}