rule nthash_hashed_default_creds_ramp_networks
{
    meta:
        id = "6aYGPGmUcBzvmlYzZ2EpK"
        fingerprint = "0a6fafb36d4aac6490e5669ab1a7066b4b786a5566b82a83e38f58d4c0801bcb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ccf0e02493b091bd69dafa58f082a35"
    $a1="e8e7289454393110d7d4bc415fd463f4"
condition:
    ($a0 and $a1)
}