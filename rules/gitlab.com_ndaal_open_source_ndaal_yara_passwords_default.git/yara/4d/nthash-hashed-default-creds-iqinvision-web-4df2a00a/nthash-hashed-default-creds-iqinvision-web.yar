rule nthash_hashed_default_creds_iqinvision_web
{
    meta:
        id = "7LTj4aUWzAcz4PhYfwwQiy"
        fingerprint = "9531610d9c9b16cc04d6917706ae78777abb3549fffa8843a0e770f83f0b5b3f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for iqinvision_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}