rule sha3_224_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a4="65ec07d421a61b431fa1f4dfe8447644927823ffc9e5ed15743fcae1"
    $a5="65ec07d421a61b431fa1f4dfe8447644927823ffc9e5ed15743fcae1"
    $a6="add94bc310841f2297286a9b76d4a652f6a230f8899126f588afef59"
    $a7="fae58965751ca3b5f7490c7ff429ff3c92b5f1ebb06edcbe8a102ba3"
    $a8="a9ebf1937a742d3c21b0794419cd477017ce3728b1702a7728f17bae"
    $a9="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a10="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a11="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a12="50e7f91e037877cd8a809c4f7a2812f9ace7bda5f895896c4e2eea1c"
    $a13="50e7f91e037877cd8a809c4f7a2812f9ace7bda5f895896c4e2eea1c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}