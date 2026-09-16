rule nthash_hashed_default_creds_mike_peters
{
    meta:
        id = "5C3GID1LTZdKch9t18Qw8m"
        fingerprint = "8045acb69c06489306828646f0b69ae6ea58734cb9025b5b045bf82338ded314"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40679c617609f3a2351c71c0678ed62b"
    $a1="33e2519bfe543235310ba13e97485539"
condition:
    ($a0 and $a1)
}