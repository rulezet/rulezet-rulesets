rule nthash_hashed_default_creds_kti
{
    meta:
        id = "6akSMLGYWadGQzvw4kxlQy"
        fingerprint = "737c94447602a7bb2b1b7f5fb6b4c9bafaa9379cea56348f3a05211502cd2d47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kti."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="32ed87bdb5fdc5e9cba88547376818d4"
    $a1="8f62e69c0919247c923b60a23c0e46b4"
    $a2="3dbde697d71690a769204beb12283678"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="32ed87bdb5fdc5e9cba88547376818d4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}