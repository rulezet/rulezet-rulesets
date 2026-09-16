rule sha224_hashed_default_creds_episd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31b7d4391e3c3baee2f06d45fa50ff36c622bcf17d34f183deae307d"
    $a1="00aea1ea2d7e2f8ed62b68883f7be17ba58145a070e1c82d954eaf6b"
condition:
    ($a0 and $a1)
}