rule nthash_hashed_default_creds_adaptec
{
    meta:
        id = "7HbcP0OhgfSqYUFqrilkoX"
        fingerprint = "c0fe35dcccdf9d404c849736ab3c47a2721778b4abbb4dd2d11060cbf5d6c422"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adaptec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bd329279b1545609178468c70dbcf340"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}