rule nthash_hashed_default_creds_raritan_inc
{
    meta:
        id = "1gWc7apiEHmSYr4ZvHFqeo"
        fingerprint = "bd9ac49039f79adeeb8b7840e11ab5d6adfcfd93f2e24778629fe415b38d3841"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8749288952ede39aa677d5eecd6145a7"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8749288952ede39aa677d5eecd6145a7"
    $a3="837320dd341ee09fd9b952e4e33b35f6"
    $a4="b75d67d5262c636a684977b47a9d991e"
    $a5="cb9765b786722cdab4b7df7e4a42f04c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}