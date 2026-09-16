rule nthash_hashed_default_creds_riverbed
{
    meta:
        id = "33NLi1IGmTjo6PaOpxbw6s"
        fingerprint = "4e6c2b1eeaebfb0837ada2ca02a45f540308e10849cdeca61bc3079583459af8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for riverbed."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="a25b2710ba9de114396adc7dfb0a7235"
condition:
    ($a0 and $a1)
}