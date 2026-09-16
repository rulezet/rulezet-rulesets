rule sha512_hashed_default_creds_cassandra
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab6a34a451b061203fb9e7cbeae89f8b94c4d42ee38a88fbd6f5830dddf9efff3ace6d4fec6d9d6dd1596ce517a42fe06d0e4ab7e8c342391662871fbc5d9a02"
    $a1="ab6a34a451b061203fb9e7cbeae89f8b94c4d42ee38a88fbd6f5830dddf9efff3ace6d4fec6d9d6dd1596ce517a42fe06d0e4ab7e8c342391662871fbc5d9a02"
condition:
    ($a0 and $a1)
}