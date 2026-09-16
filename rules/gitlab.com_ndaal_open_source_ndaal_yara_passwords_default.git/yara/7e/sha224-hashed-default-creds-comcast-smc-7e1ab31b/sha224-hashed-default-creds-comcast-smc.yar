rule sha224_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="583ae0e505c9e885b69d5affb67d103507b20edb7d2e3bb65928c441"
    $a1="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a2="cd67b76f75f4577b8c0f9541bb4658e24a34ee90a9fbe4f3a46bed80"
    $a3="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}