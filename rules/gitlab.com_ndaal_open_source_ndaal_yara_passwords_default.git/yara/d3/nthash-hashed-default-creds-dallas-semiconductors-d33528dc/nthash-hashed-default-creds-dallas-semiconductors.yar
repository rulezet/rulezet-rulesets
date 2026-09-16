rule nthash_hashed_default_creds_dallas_semiconductors
{
    meta:
        id = "4EJZDqSYH8fOygiybhbJs8"
        fingerprint = "52e25f401a6c15494baee95797764c2001475c6446446aac81f432cb71eaff95"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dallas_semiconductors."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="024ab850b9df52f6b5fe10ba0e8afb17"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}