rule nthash_hashed_default_creds_timeforce_mssql
{
    meta:
        id = "7PR9bYYbF29BeTUJGd6BJl"
        fingerprint = "e0045d53970254ee382002fc0587880c79a2a17f5ac9599c942a0031813d6eb6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for timeforce_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e05690f8dea325c222d1f124dd7e321d"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
    $a2="ce5f1d3487b2053ba4fd64a435a5b765"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}