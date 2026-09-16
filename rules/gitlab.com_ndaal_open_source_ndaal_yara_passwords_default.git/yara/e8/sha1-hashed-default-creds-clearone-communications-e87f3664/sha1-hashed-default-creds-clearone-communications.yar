rule sha1_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ab3280796d42482db99c556659738bd05f2ac46"
    $a1="f30ef8daf52bb4b7faceba89c9383a6a0775651c"
    $a2="e7e4c6be1280d12bc9b2b755037f0ee880bd2dbc"
    $a3="81c9dadde7936f7d5d1877e0287a044c36954397"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}