rule nthash_hashed_default_creds_teltronic_sau
{
    meta:
        id = "5CeLZ200VB8hQwGhSm7C3B"
        fingerprint = "c5e5bb87e829cb79f5c84be22f5033a11cabf81a987b1e8b142cecdaa5fa26ea"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for teltronic_sau."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e4894aabe071b59d1492f56a958b69f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}