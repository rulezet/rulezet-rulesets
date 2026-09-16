rule sha384_hashed_default_creds_frontrange_solutions
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for frontrange_solutions."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49e18e684812e9034a6c1eef90b337cbc9ee8de6383e57b79f4bc255393417ab33def30f0f3398c5489c00faab52a619"
    $a1="233a0c3b653358b1b07cf093e7b2e36a54bf4c66d5736db17ed145b18520c9108bbd9ed53bc74de041e15f1476013b10"
condition:
    ($a0 and $a1)
}