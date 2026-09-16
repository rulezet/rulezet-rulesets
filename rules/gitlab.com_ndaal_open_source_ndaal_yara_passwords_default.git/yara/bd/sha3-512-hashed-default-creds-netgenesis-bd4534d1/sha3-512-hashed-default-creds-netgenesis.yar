rule sha3_512_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="004fd741b37dff7b79b13c1737631970dff6fba29d668784017345d5d8d05f50c3a26d81102276eabf54d2588250f44f89ecd06e5c316de14748c350218af8bd"
    $a1="004fd741b37dff7b79b13c1737631970dff6fba29d668784017345d5d8d05f50c3a26d81102276eabf54d2588250f44f89ecd06e5c316de14748c350218af8bd"
condition:
    ($a0 and $a1)
}