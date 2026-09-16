rule blake2b_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e16e38a0bc5af9028b4d0a97063659a53b65a4b177cb3ed7a220a22f415edf82df51f4c4ef180072568adfd3121f04b2a6ca86356f05a1bba513f76fe94999a0"
    $a1="78618dfd6cc2037c478bbd350b683130e209f5e6a2ea4d686ae9cfd276c2b898bb004a172382ee5a158945166b46a9cf6c6c37e21eebb9658a00a75f0d0da9bc"
condition:
    ($a0 and $a1)
}