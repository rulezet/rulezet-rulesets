rule sha3_256_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54dd7d295ea01bf21b7a2b38cd8d21da36402a52209784922bcc4f52c540ca79"
    $a1="d325d41ae8a7fd3c30f998af5d10e4042345a36696f4abb09ab707e9e4eb9045"
condition:
    ($a0 and $a1)
}