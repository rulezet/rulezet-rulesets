rule sha1_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="966355535b56f1ab69d1be7297722bff45943563"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="e52c854d5631eec7468ba4727b4c77eb745f2965"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="84c29015de33e5d22422382a372caba5c58f8c01"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="ea8b8d89e4b7320d73236b375a7683a4ccd3a296"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}