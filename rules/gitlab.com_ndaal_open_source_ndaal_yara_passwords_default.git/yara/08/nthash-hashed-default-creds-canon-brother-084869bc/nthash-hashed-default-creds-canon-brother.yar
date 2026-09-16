rule nthash_hashed_default_creds_canon_brother
{
    meta:
        id = "2GWN1QbHE4U489cszgu3zr"
        fingerprint = "aa9411e57ef3444083a5e46f8746a4ec4bc494981dcfb34b806b962304265ce0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8bb80565a55deaa6e1847dc1bc3505fa"
    $a1="8bb80565a55deaa6e1847dc1bc3505fa"
condition:
    ($a0 and $a1)
}