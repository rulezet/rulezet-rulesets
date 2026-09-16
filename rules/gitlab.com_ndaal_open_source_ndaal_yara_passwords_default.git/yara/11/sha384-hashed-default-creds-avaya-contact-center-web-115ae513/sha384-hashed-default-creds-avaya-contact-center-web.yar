rule sha384_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
    $a1="cc741da44e4d00e88805b9b575c675e88d69a66380985fdb4421d0382a31ff08c6ba9433d04f7707f029200bbb3096c6"
condition:
    ($a0 and $a1)
}