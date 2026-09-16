rule sha1_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e38ad214943daad1d64c102faec29de4afe9da3d"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="2bfb09e2c7a43adde0c3f986fb5d0563d8dfd5f5"
    $a3="4aad0471e6ce1a8b8c30b3b77fa8370ea12552eb"
    $a4="b703589b93f4f64d7963ad193f65561a001e9825"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}