rule nthash_hashed_default_creds_cellit
{
    meta:
        id = "52r5DRtVjZK8QGDiOhQOpl"
        fingerprint = "6852bb45d6037271caae18e98b7dc965a38cd91bd44b1f874f3f0f32553c0d23"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6425482c051110435000963520a68e31"
    $a1="6425482c051110435000963520a68e31"
condition:
    ($a0 and $a1)
}