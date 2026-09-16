rule sha384_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a1="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a2="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a3="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a4="2e157da6de9055f70e39d07ce58370c8d355b304a159bee4d5858fed189706a4f7a1adfe272bab9324948123aaff3155"
    $a5="2e157da6de9055f70e39d07ce58370c8d355b304a159bee4d5858fed189706a4f7a1adfe272bab9324948123aaff3155"
    $a6="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
    $a7="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}