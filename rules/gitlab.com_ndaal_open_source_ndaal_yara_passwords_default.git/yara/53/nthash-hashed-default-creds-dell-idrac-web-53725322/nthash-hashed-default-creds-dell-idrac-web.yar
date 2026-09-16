rule nthash_hashed_default_creds_dell_idrac_web
{
    meta:
        id = "6AkVCoJ4mmJTEy7MsYgt90"
        fingerprint = "2e54d3ecdb0f915383fc0783e8e6c6e55d7404a52282e80e42448b1530d86cfb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell_idrac_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c7881d6a4603ae3bc7dba0fa8b6a3b7"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}