rule nthash_hashed_default_creds_pollsafe
{
    meta:
        id = "2OoY5NRK2JEppJmYLEqL3N"
        fingerprint = "e46739306a6739e4eceafc192599b80b91706574a87aa3cc8e8ba2e8a6083c56"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75f67de9b91dce844c9783837761622b"
    $a1="793c81b3c6cf818021aa4e790fdf3387"
condition:
    ($a0 and $a1)
}