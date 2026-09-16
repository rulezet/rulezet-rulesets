rule nthash_hashed_default_creds_davox
{
    meta:
        id = "62jRI15RzKVck4gmETlIPr"
        fingerprint = "468640ad2292c1936c69c59530dede5568115e76293809a6d65e8db5cc3262be"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davox."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="acf6d2f7cf296ba290f2524fd9c29762"
    $a3="acf6d2f7cf296ba290f2524fd9c29762"
    $a4="acf6d2f7cf296ba290f2524fd9c29762"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}