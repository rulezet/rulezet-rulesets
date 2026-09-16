rule sha224_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a3f46b8bdd14b4a819c84c43c2f1aeefba0adcb4839aa354c6a4b10"
    $a1="748b089a11fe5e4d08577d53134155745e791f49f677ac44ed554354"
    $a2="fb18dff476b2148de33fd3122f9589d39236ce4fb8a7956176bd675d"
    $a3="22020dc655d0f086116d2e85bd6c9301f3ea9cbf3a9bcf490e28d3d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}