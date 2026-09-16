rule nthash_hashed_default_creds_intermec
{
    meta:
        id = "1FckVwGyqTZeBRndBzI6kG"
        fingerprint = "c1250cc5deeccb6cd5dcc8c9a6144629bdabc287a8385ded984db253c50d320c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8ae861c7a35cfac92f4ee90719b6c05"
    $a1="e8ae861c7a35cfac92f4ee90719b6c05"
condition:
    ($a0 and $a1)
}