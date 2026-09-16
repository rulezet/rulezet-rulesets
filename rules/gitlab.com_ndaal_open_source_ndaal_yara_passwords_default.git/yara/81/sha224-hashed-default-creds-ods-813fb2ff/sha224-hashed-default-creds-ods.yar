rule sha224_hashed_default_creds_ods
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ods."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="155510e79e6b0637165ef3a3b90465a4a04f7e7c1237a9f68059e631"
    $a1="155510e79e6b0637165ef3a3b90465a4a04f7e7c1237a9f68059e631"
condition:
    ($a0 and $a1)
}