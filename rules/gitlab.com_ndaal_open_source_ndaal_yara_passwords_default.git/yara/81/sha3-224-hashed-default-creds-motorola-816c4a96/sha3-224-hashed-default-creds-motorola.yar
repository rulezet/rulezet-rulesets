rule sha3_224_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="283b91b42fe837604b6c486310061312bc2887abdc821416b858521c"
    $a1="3d485d081fd9f8aeab0a900813700d2ffffad79267748f753b6438c1"
    $a2="0f0a9fef8fcc761fcfee0e6757bfbe09741361f7b7df68ca20eea036"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="fd9dc48ed52245c81385c2a50f69254ef2318efd51650adb441113cc"
    $a7="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a8="fda7b94b1afd7d51ea37c37632bb79b0f19499cd05cb47d58b7bab2c"
    $a9="3ee9a89c78349023a55c7e7b2f67e2c8de518495961090c74b91356f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}