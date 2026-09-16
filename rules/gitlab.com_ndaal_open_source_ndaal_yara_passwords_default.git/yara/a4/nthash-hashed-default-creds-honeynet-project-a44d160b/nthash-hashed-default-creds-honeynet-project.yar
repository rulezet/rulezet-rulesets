rule nthash_hashed_default_creds_honeynet_project
{
    meta:
        id = "4PzBTtDovxPzAhlc6rRQsq"
        fingerprint = "3789cf3c106727d447091aa9f77abea44f1a4d3dc37cbb62c776a1d05e848dd3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a319c268a4be273a28450db17e6c18e"
    $a1="ff07c85ac048b4ca8e94a226d7ee1f27"
    $a2="3a319c268a4be273a28450db17e6c18e"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}