rule sha224_hashed_default_creds_cassandra
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102cf74ee5d9504953de671e6e179b17a63f038dbb26d8abbee8adad"
    $a1="102cf74ee5d9504953de671e6e179b17a63f038dbb26d8abbee8adad"
condition:
    ($a0 and $a1)
}