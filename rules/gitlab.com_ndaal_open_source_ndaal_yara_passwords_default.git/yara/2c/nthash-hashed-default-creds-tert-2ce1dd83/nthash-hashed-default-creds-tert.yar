rule nthash_hashed_default_creds_tert
{
    meta:
        id = "DofT1jiM8BNU27YVPxsXA"
        fingerprint = "eef48d6d01f1ab4af15c1e085cb8218be15b1648bcb5c0a57b55b2bbe34289e1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="494877a3209b0ef206a36248e245f2a2"
    $a1="494877a3209b0ef206a36248e245f2a2"
condition:
    ($a0 and $a1)
}