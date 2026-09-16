rule nthash_hashed_default_creds_apc_ups_web
{
    meta:
        id = "4zI3WBouVZo3WzRei4OH9I"
        fingerprint = "0f8ecdf434b920802d83c84eb35fbf09b5698715931dc79765a96af96e10d8d3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b96670ba87df193012a9b0ddbf14c634"
    $a1="b96670ba87df193012a9b0ddbf14c634"
condition:
    ($a0 and $a1)
}