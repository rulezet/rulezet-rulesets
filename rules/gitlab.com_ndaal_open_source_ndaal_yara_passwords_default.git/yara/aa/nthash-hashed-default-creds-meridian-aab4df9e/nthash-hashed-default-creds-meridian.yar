rule nthash_hashed_default_creds_meridian
{
    meta:
        id = "3zRKZKyIoY3Wx4xcCenpSF"
        fingerprint = "8b8c1e073d87200d78241155347d4548aee2f7746d67cb265c73bbdac440ef52"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for meridian."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ba57c94d500dd36627fde8fc037393b"
    $a1="f07206c3869bda5acd38a3d923a95d2a"
condition:
    ($a0 and $a1)
}