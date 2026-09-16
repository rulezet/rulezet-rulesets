rule nthash_hashed_default_creds_opengts_mssql
{
    meta:
        id = "6ZwrCSGMAJNdOXCmyBlY9r"
        fingerprint = "03ab68195bcb85c06314c33a10fa127196e6e54c48e903913d6c4637762004a1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bdc5270d51e7e67a091ff31b6e2a5027"
    $a1="e4f81996ed2bda108a1669708c9a453b"
condition:
    ($a0 and $a1)
}