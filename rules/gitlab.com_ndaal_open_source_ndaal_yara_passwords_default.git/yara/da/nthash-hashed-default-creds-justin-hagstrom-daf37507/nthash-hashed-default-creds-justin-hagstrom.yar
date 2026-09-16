rule nthash_hashed_default_creds_justin_hagstrom
{
    meta:
        id = "2fzDvdFLyllAcDC4qNZtya"
        fingerprint = "b35189cf7ea56ab7b7f5b91e173d6ecd50031a118d35d849adbeafc84c062aa0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for justin_hagstrom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="0cb6948805f797bf2a82807973b89537"
    $a3="0cb6948805f797bf2a82807973b89537"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}