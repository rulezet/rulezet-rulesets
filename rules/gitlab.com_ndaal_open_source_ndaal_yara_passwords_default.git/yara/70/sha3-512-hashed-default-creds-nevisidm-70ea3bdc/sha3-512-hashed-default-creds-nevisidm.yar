rule sha3_512_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff7d60eccc07fa23d33bbef9701d2d163fb822d6530e82280c8c05ae298a82cdbcb4bb3fce63340a3231b837bc42abb57200a8c0a4d51eb38e8865b5a47b8258"
    $a1="741e0da10325acae9106891bf28cfb0d80ea1ef9938b2660db9c8e63242f48bd3cead5b0e18aa48ded525ef8135071b5a4b1294c630c48f278cc20f60211bf2b"
condition:
    ($a0 and $a1)
}