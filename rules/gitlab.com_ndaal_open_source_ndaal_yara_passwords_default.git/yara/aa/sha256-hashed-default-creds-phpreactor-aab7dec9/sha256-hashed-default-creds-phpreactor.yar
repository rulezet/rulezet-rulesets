rule sha256_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7672dd2edb47af6dbf8a18e6ec217b17edcb9531acde1028d248a7ce5a744ddd"
    $a1="0d45f5fd462b8c70bffb10021ac1bcff3f58f29b1faf7568595095427d42812c"
condition:
    ($a0 and $a1)
}