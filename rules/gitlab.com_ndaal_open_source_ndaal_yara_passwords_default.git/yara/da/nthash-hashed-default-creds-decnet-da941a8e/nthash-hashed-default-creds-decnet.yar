rule nthash_hashed_default_creds_decnet
{
    meta:
        id = "4ryvDcgN54uRp2zFPYU7nX"
        fingerprint = "3a04c940685b4568041b473f2b4bf2df5a0aa8a85f1ef11dcac22ac95185473f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for decnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="e337e31aa4c614b2895ad684a51156df"
condition:
    ($a0 and $a1)
}