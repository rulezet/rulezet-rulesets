rule sha3_224_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a2="0be990d7a9d0725d4109145a6454011ba2b98f4df551faa5cff989c7"
    $a3="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a4="8f4ed792f5ecbdef4a7d813a9624f71e924ac4f63eb75408fcd0f897"
    $a5="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a6="8d7a2be72d89dc32f516c2bd0f960f3f0f32fc0733f2e8373cc4d5b5"
    $a7="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a8="38a99f28118b7143051a3d2ab3719a64061501003cfa1b7949648495"
    $a9="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a10="bf5b5c7f32e8b4ae23803af71b0f1c6eab4508378e00ea966d652979"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}