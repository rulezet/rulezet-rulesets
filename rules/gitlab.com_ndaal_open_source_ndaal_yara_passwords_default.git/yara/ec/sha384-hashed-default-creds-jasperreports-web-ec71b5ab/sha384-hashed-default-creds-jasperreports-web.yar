rule sha384_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48edf17268dc2f757b35d442d540f840809a974e289721019d101d8e3552e2abd5f68c16599a531ea361d370822144e7"
    $a1="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a2="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
    $a3="51e5c804068fd73c1ccf05718c3937d625abb2051d61c0acc35f447b1ba3684609da4f914ce0d0cd2978310e05b5b075"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}