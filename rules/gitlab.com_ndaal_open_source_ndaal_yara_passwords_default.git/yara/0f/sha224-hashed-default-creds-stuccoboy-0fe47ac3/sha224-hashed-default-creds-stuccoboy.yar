rule sha224_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a1a6b7738e0a5f459b026147da6aced8acec43d5fd784cf7a800459"
    $a1="0dd86c1eb1645cc43ea738d02b3977e9cf4ba85905d4668b31d9e9ba"
condition:
    ($a0 and $a1)
}