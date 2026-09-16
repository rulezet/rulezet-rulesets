rule nthash_hashed_default_creds_wellintech
{
    meta:
        id = "7OzcJB5jpGnOeDTjmvJUlh"
        fingerprint = "b850c4a69fa0e1bc1f76e0e434cbc8709b27d1f8bbcc5330c3a4696447508024"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wellintech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4141712f19e9dd5adf16919bb38a95c"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}