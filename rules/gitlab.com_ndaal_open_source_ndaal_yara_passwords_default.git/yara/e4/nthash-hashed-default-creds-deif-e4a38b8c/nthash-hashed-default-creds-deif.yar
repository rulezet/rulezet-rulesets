rule nthash_hashed_default_creds_deif
{
    meta:
        id = "7a6LyBBNxvoWpoHmASB9kt"
        fingerprint = "a8cf2fc4827002f5f2567347377ac721841253b7f2af7c609a06108aa81acb32"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deif."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f7cfa41277214fe52852276a8ffd41b"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="7d891ab402caf2e89ccdd33ed54333ac"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}