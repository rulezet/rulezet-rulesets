rule sha256_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30eaa4e621d188cd12f986718055ac1990811f46ca16760abc5fb4e31a6cd2f9"
    $a1="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a2="d6a7cd2a7371b1a15d543196979ff74fdb027023ebf187d5d329be11055c77fd"
    $a3="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}