rule blake2s_hashed_default_creds_globespan_virata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for globespan_virata."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="895efb8f3cdbb394f6d70e95898dc01280b992f9a3589a8301d0b7122e1f6dfc"
    $a1="895efb8f3cdbb394f6d70e95898dc01280b992f9a3589a8301d0b7122e1f6dfc"
condition:
    ($a0 and $a1)
}