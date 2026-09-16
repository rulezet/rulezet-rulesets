rule nthash_hashed_default_creds_stuccoboy
{
    meta:
        id = "1VHtE9ntnjiRxuVcPFAiHM"
        fingerprint = "121e0d7010ce0769e919e519ef7e6adc92d973c3bbfec465e22452481869b200"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47366bb9ac91c197b5369e6a7c0c79bc"
    $a1="53b6753bb853a38efdf082dbfd13e74f"
condition:
    ($a0 and $a1)
}