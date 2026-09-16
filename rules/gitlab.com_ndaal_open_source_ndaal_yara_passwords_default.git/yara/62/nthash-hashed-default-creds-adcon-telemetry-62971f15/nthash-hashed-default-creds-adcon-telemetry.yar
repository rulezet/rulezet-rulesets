rule nthash_hashed_default_creds_adcon_telemetry
{
    meta:
        id = "6QPbeGu4H7qDWNdr4kx2Zo"
        fingerprint = "bcc92863ce0f17418b82ee1995e3037a2a436392412d9c494d8021b73631c83c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcon_telemetry."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46811ed15607e16977370403df00500e"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}