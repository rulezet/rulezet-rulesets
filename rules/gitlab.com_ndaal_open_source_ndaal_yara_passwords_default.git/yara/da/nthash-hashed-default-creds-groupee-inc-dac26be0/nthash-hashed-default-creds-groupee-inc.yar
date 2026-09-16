rule nthash_hashed_default_creds_groupee_inc
{
    meta:
        id = "YD3tQAVpHt3URQrhRfz5G"
        fingerprint = "f08a1b4d91f1173d8fdb74e6be1f30d443548747cbc615c074c7b635cfdba980"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9491ba243c73be502170aa8e90fc1acc"
    $a1="7337a75e9e5a2b6b2b958794dd75457f"
condition:
    ($a0 and $a1)
}