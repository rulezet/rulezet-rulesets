rule nthash_hashed_default_creds_cyberpower
{
    meta:
        id = "lkNJ9rzHdK6T20w3iJog1"
        fingerprint = "88cf7f9bfc8f131662845adcbf348d682a93e323d876a548965f97b1d53c9754"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff5dac435f926d9c7bae66d7836e7c04"
    $a1="ff5dac435f926d9c7bae66d7836e7c04"
    $a2="ff5dac435f926d9c7bae66d7836e7c04"
    $a3="5d93591697ff29acfa4eb6a086205cf1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}