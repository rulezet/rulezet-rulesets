rule nthash_hashed_default_creds_next
{
    meta:
        id = "7U88nvYCoDWzCn6jDM8Xfg"
        fingerprint = "f06051ecd009a18fb43734de83741fa81b882f75a07aa1216e4744d07dae914e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="942eb66be76475de7a06013939eed27d"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="e37adf58eeed64deba316c9a84e5ebcc"
    $a3="e37adf58eeed64deba316c9a84e5ebcc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}