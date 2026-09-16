rule nthash_hashed_default_creds_safenet_sentinel_ems_mssql
{
    meta:
        id = "6WTgMGIl84N5gXXHsCzCXf"
        fingerprint = "fcf1acf69de261567586c175a57d519ed29bbeedd7b5fffb2a7ad44321d4a5d3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for safenet_sentinel_ems_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f842a79fdf4ed6accf798f0224bd3cc"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}