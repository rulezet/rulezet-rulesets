rule nthash_hashed_default_creds_mediaportal_mssql
{
    meta:
        id = "77YkdyOKYmP08vZwsew1xl"
        fingerprint = "fb9b7f5bbe989dd11d7e01eb67ffa7cd52e240d69179ccb971b8f22de720b912"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mediaportal_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a5ba4e3748d161b6b16d987ed220477"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}