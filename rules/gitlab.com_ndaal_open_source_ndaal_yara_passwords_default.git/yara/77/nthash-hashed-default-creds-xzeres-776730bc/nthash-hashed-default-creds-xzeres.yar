rule nthash_hashed_default_creds_xzeres
{
    meta:
        id = "2ZbPTKGsjTsSQA1JVgA1JL"
        fingerprint = "0202941819faa7145312b732c08c05c53f7d7d02b46395d6120bcacdc3381bab"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e681cae8a397031b20eb9958894cf8d7"
    $a1="760527cd2d1d25951523f858c7806311"
condition:
    ($a0 and $a1)
}