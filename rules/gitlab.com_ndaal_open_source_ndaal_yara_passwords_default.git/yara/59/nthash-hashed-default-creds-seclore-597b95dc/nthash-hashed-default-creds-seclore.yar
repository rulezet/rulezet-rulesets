rule nthash_hashed_default_creds_seclore
{
    meta:
        id = "4ptUt3vag0A69DB5ub1ILm"
        fingerprint = "6a348e7182d0638cdf25a5299355c2dc6dd00b4798d9b36bc6fbbb8a3b242fc9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e765b5ce499d7088f0356ace07c7ca8"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="4e765b5ce499d7088f0356ace07c7ca8"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}