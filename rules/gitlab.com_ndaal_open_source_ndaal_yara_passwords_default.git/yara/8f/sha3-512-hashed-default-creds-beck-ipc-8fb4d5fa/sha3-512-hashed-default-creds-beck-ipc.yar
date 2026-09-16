rule sha3_512_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a297889be88590dcad6d51b2b7450f2341965fcf5389eb3a6e9ad321a5d735bed8af6a6fe6d62a441b823f69be4d98a1c86a396676718882bc2c9e9c8bdb9929"
    $a1="a297889be88590dcad6d51b2b7450f2341965fcf5389eb3a6e9ad321a5d735bed8af6a6fe6d62a441b823f69be4d98a1c86a396676718882bc2c9e9c8bdb9929"
condition:
    ($a0 and $a1)
}