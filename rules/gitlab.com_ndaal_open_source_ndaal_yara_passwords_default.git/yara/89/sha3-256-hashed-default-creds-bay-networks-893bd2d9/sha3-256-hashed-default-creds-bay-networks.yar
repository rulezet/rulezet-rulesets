rule sha3_256_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
    $a1="10414145323772df86d67f55a07a80e989ba7d893f8fa9a79031b2d7000ecdb9"
condition:
    ($a0 and $a1)
}