rule sha256_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eed59b8a79fef142936244983c1fb3cc2987d19c5d8029b61a25c73184c6ad42"
    $a1="f642974cfcb13951bb7d2f007a01d957bdde662a313a3e5c2cb08bb54f16f07f"
condition:
    ($a0 and $a1)
}