rule nthash_hashed_default_creds_metrobility
{
    meta:
        id = "64Qn0UIclmO9tWq2XhT30S"
        fingerprint = "e09bf3a0feace123cd43034f2e1424ea7d4c80629a5fd2881d4e02f96949a98c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metrobility."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="823893adfad2cda6e1a414f3ebdf58f7"
    $a1="823893adfad2cda6e1a414f3ebdf58f7"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="329153f560eb329c0e1deea55e88a1e9"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}