rule sha3_224_hashed_default_creds_cassandra
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2ccf24fb37be226273b73eb1f23a77df667294c6bf5557597bd1e46"
    $a1="b2ccf24fb37be226273b73eb1f23a77df667294c6bf5557597bd1e46"
condition:
    ($a0 and $a1)
}