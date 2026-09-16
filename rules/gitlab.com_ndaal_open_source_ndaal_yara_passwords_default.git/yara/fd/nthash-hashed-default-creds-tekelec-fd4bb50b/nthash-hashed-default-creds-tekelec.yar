rule nthash_hashed_default_creds_tekelec
{
    meta:
        id = "3IRcUNEHMoSkhWpoPHfkl8"
        fingerprint = "db068cdef6f2dc993134ddfa5d0c594090b5ce406c9b05efc0c9593417ab6cec"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24cc4d247bf23904b2f42606040369a4"
    $a1="24cc4d247bf23904b2f42606040369a4"
condition:
    ($a0 and $a1)
}