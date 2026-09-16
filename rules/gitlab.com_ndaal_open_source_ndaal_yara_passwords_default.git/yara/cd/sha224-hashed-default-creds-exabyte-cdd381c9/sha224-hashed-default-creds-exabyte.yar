rule sha224_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4dbc2e711896cc9b90f709a91b8239b5f613504b3ebbe95d8a18c8a1"
    $a1="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
condition:
    ($a0 and $a1)
}