rule sha1_hashed_default_creds_nullsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nullsoft."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1)
}