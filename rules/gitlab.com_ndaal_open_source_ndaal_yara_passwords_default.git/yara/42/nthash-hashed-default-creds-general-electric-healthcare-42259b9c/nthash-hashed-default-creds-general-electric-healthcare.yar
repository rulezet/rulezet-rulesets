rule nthash_hashed_default_creds_general_electric_healthcare
{
    meta:
        id = "3G8fcZBgKoB31fo3n0wBAH"
        fingerprint = "1e15459587a2890068e35fe191c0734ab82c0d9180a5dfd033f0915dff13411b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
    $a2="6870185312c803240aa99c3702639da9"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="6870185312c803240aa99c3702639da9"
    $a5="6870185312c803240aa99c3702639da9"
    $a6="769ba068568072b10b2c0d2e0f02ebab"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="8588ebf11ee2219a33e70a21b6bc6866"
    $a9="9b3b43a7ba16b656900d947cb9862e23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}