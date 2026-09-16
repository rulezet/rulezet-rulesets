rule sha3_224_hashed_default_creds_adp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
    $a1="b3c613fcea10ca76dab2bae1ff0054b92d46aead56580e60898b6f82"
condition:
    ($a0 and $a1)
}