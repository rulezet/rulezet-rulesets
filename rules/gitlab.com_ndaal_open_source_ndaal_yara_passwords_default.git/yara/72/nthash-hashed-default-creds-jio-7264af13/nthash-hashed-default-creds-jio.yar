rule nthash_hashed_default_creds_jio
{
    meta:
        id = "KwtqNYYu3D5ZcazAdO7wv"
        fingerprint = "5702ff7ae94f2b3c3e003c68535169a4114334277552c63d859f98c31c04713b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="622e3f0665ba6c932a29d844ee89a3e5"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a4141712f19e9dd5adf16919bb38a95c"
    $a3="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}