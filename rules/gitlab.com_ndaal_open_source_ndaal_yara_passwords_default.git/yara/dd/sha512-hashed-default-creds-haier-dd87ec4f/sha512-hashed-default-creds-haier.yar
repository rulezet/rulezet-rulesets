rule sha512_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b219732ab627ffa521fdea8f9adb17a56a1fdf75ca01ae5196a439cfa34bb1852c47e832f5cda7322e8176559b6ee072db0ad7d9941f270253dff4ccceb81b3b"
    $a1="6d41530a870f29e808902d51c4c6dd83c98e37ced7680ee3de93a6439f65adfdb6749fa13b652f234d72a43bd0fc158dc84380b767b1a3c84c5149d451333b97"
condition:
    ($a0 and $a1)
}