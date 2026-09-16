rule sha384_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8677fbf1106acb063373e0f49121314986c407b58a4fb512218e262106471c49753fc6577d8cc40f7147f6c16775c21"
    $a1="a8677fbf1106acb063373e0f49121314986c407b58a4fb512218e262106471c49753fc6577d8cc40f7147f6c16775c21"
    $a2="88e8b2edab814eda3871b06823ed4fad1b6d307087517e6d10a916974a9aab7191f070d3ac8e18bbf9fdd0e36fbdd29a"
    $a3="f4ab68cbba51b1c9d19d3924035bd441846ad956b277ff02600a0e1f8601ca01b5b0f2a2c05776c7ec66168de3a808fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}