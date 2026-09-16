rule sha3_256_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="379f62a058f3d0222386d4474c65c91d16326bac4e85862667aa62efaab973d8"
    $a1="aa5d959f275209a04016ff431c70348dd1ea5ce398823794c559e5e74a44762d"
condition:
    ($a0 and $a1)
}