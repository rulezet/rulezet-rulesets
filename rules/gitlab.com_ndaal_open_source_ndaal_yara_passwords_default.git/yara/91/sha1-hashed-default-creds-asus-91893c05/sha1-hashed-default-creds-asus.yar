rule sha1_hashed_default_creds_asus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asus."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="f40b27d6b8b9a4fc3827264c1da16a04ecf4d094"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="8709b4e821e63361cf2d1a8c2f9ad3a5cc6af76e"
    $a9="5e14ae57fe236da8d609a8d5c2b46ecb62df8833"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}