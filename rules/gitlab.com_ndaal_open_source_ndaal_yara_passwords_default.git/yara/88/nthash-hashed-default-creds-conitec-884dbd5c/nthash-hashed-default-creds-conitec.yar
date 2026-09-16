rule nthash_hashed_default_creds_conitec
{
    meta:
        id = "5SrjSfbXtsdGr6HKeYCG2t"
        fingerprint = "a12018bb400f182ee949fe949e28985ed4c5dc5ee8898487201298f9a380beae"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1cb357ea41a7266b19e5d7233786fb09"
    $a1="c2270daaf144395356b9791a5ba89492"
condition:
    ($a0 and $a1)
}