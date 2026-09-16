rule nthash_hashed_default_creds_merit_lilin
{
    meta:
        id = "2rmZAbOddbt2Woc0vMQS4p"
        fingerprint = "5a5f244e34461ed311ce654b76d4d7fc017e0bcbd936d362908d6a84adf55029"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="666eff8911fd8a13f1c10be3c4da4704"
    $a1="bd6913a0042c93f4de5b4241955ab103"
condition:
    ($a0 and $a1)
}