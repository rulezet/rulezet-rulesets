rule sha224_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b3b3a2babe1007f0905e9bc6165c8b7c41010dc1078ec61cf2e4241"
    $a1="bcdf6c448176da40e0dc194f422c2716168969aefe1e965632d71d3f"
condition:
    ($a0 and $a1)
}