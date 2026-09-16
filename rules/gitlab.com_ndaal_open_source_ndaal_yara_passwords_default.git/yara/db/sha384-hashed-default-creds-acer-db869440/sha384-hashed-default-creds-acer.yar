rule sha384_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b2e4ff6dd431e7734b45cee108a76aba75a48ceb7f51e8a8976200e0cc5ab033afbb7c18f7814500fb325a87cc7cffd"
    $a1="6b2e4ff6dd431e7734b45cee108a76aba75a48ceb7f51e8a8976200e0cc5ab033afbb7c18f7814500fb325a87cc7cffd"
condition:
    ($a0 and $a1)
}