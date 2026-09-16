rule sha256_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84ca9773e6a2ce46845b956bb2b71f1a00614c977a6504afa98bedf440390652"
    $a1="84ca9773e6a2ce46845b956bb2b71f1a00614c977a6504afa98bedf440390652"
condition:
    ($a0 and $a1)
}