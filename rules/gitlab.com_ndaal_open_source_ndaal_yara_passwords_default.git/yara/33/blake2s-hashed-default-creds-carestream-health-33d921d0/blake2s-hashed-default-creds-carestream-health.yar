rule blake2s_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c62b7fa025a37e96e0e5a6897d7878b35b87fb57cdfac6a59c03707afccb311"
    $a1="5cf8a38d67a9258564cf6df099ad8bb9b3699ef0ec57b1722d9bc819b48b2d66"
    $a2="1c62b7fa025a37e96e0e5a6897d7878b35b87fb57cdfac6a59c03707afccb311"
    $a3="35437b5e0da7d794d8acdd8fe7086bf559c45503bdab44cdc7a0261032323a2f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}