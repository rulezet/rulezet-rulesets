rule sha3_512_hashed_default_creds_opengts_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for opengts_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8005cbbea90f003347b5ff08b97f1888ae8d2d8a91b93364c5646d789c3c6e29a86a2b4f22d8ebcc050ef194780fc954c84a1606a05924b7339ed62c3f462127"
    $a1="9c2fbce30019a5c0e4403dbceaf9abe2157d15bfdfac01cece8e7c966a127bc7067fac64d83a18f6b3137dfb1ad7f64ae0d2bd8f3c006dffb232e1b118b48dd3"
condition:
    ($a0 and $a1)
}