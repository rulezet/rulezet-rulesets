rule sha1_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="2736fab291f04e69b62d490c3c09361f5b82461a"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="2736fab291f04e69b62d490c3c09361f5b82461a"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}