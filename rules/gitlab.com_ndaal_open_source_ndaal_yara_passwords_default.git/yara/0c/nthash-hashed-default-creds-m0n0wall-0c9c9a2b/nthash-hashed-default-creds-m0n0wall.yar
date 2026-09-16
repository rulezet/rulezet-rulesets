rule nthash_hashed_default_creds_m0n0wall
{
    meta:
        id = "5v7sKqZwCI16qrJ5EQuYN2"
        fingerprint = "a96fcac171ebeed2b4b4b5f995204ca86a89dc25600a879ff63cd6b72aad9afc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for m0n0wall."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9d31a2bb68d6c08133c86a425068a1f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}