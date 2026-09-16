rule nthash_hashed_default_creds_echelon_corporation
{
    meta:
        id = "30Xs1qwaX0UJs7kaUSbLo1"
        fingerprint = "a3e01e4df47cc898e870534fe4625d87c9aafa244ad7821e20b54d1b9944f1d4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff765d296da26840854d84126e8ddfb2"
    $a1="ff765d296da26840854d84126e8ddfb2"
condition:
    ($a0 and $a1)
}