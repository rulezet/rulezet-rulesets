rule nthash_hashed_default_creds_micro_focus_silk_central_mssql
{
    meta:
        id = "3VjQopyOYoikj3a9G616P9"
        fingerprint = "a9c0be5842a70a1638b288937490b6bd85e8ed392d4b099a0f8daa548a5eb667"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for micro_focus_silk_central_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38c10a82602be7c44bdaffb9721b2791"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}