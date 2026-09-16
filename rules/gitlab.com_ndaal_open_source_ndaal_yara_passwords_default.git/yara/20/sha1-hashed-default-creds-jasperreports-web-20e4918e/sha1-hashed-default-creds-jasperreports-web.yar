rule sha1_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66cb456a61282953f212a6ef8ee6363acfb8fb7c"
    $a1="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a2="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a3="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}