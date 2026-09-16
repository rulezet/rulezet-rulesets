rule nthash_hashed_default_creds_xd
{
    meta:
        id = "RSj6s06u7x63R1Tuik13d"
        fingerprint = "b7eab5469a8234dfbc9c6ee9a1c03583229fdac28325fa4fd0116ddb9b222037"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fdf549ed5be3cb67401a826e30af9dbe"
    $a1="fdf549ed5be3cb67401a826e30af9dbe"
condition:
    ($a0 and $a1)
}