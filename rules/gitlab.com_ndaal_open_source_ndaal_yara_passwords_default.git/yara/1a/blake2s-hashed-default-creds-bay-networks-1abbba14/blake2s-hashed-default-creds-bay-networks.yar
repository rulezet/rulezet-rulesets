rule blake2s_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
    $a1="5ef65cc2ca9c5aea4bd3a676ebe0d4d0830ef86d040b6612912cfa92a177e919"
condition:
    ($a0 and $a1)
}