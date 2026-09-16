rule sha1_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="34c6fceca75e456f25e7e99531e2425c6c1de443"
    $a3="34c6fceca75e456f25e7e99531e2425c6c1de443"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="4fb0e878fe9af4670b2e9aa83ba44b32da427799"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}