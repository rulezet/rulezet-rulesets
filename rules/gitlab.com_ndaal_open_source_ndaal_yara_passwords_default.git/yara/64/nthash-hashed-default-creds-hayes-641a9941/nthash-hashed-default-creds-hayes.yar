rule nthash_hashed_default_creds_hayes
{
    meta:
        id = "19a58mRxKpSgItORIhyib9"
        fingerprint = "eb3e9c884183fb5e179c12a24699e54ba0c6c4d1a42623cf0aa23c1b4fd8d2db"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hayes."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="659a32a8cc56a2d3b1ae5f2026473c5d"
    $a1="f441f41aa59214cccc3d4ba5ed1550cc"
condition:
    ($a0 and $a1)
}