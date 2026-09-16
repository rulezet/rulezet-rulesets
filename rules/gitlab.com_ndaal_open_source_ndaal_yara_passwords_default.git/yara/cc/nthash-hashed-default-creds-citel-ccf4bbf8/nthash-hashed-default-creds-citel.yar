rule nthash_hashed_default_creds_citel
{
    meta:
        id = "2z1ueDAucNPhYWHFb3Rj7j"
        fingerprint = "1afbec814a9ce142f8d63e7d89d3064c4b78cc2ece3900229c255f8e9e051e64"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="66a354a124b42f320a2d14cd00d8d2c2"
condition:
    ($a0 and $a1)
}