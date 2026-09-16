rule sha384_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
    $a2="8443b821a4931ade157c2895a9ebc37dfa909fb918785a8f53f929980b3a2f9750df0ed1e437bcfa9632dbc188d55f34"
    $a3="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
    $a4="36200e17d899777de018dc515a1a4103a047ef73cc71d10568e30f2b3a10952db04c47088c99fea25f42fa7aea986133"
    $a5="7cc85315924bae71cd2b761ce69cdad4bf281f44579af5f0c406c310f9da1f42ea97620ca5d8d2221711f75346525e28"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}