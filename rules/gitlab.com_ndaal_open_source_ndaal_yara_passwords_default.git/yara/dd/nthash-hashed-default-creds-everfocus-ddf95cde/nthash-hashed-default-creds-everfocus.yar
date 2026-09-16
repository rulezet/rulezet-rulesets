rule nthash_hashed_default_creds_everfocus
{
    meta:
        id = "3tRfnIhpJVbLrRe9L57HbC"
        fingerprint = "01f431b2aaa65364e0572a345a2242938d3742ea4fd412971070fc8dd5fef3e1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="e337e31aa4c614b2895ad684a51156df"
    $a3="e337e31aa4c614b2895ad684a51156df"
    $a4="b547e99ae0f3800915f05cb7a152da11"
    $a5="b547e99ae0f3800915f05cb7a152da11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}