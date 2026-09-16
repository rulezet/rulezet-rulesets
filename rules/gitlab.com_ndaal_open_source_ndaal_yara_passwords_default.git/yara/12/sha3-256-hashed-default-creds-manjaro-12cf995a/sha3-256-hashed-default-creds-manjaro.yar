rule sha3_256_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fd3561002c724955ac67802df8148a46da29c772aa8795babed0e38896820b1"
    $a1="7defdb045e7e527c20174f1ad436860d9f8ee58f22178401553c6b5ef38e5218"
    $a2="6fda8afd648bb8717964ade45d3165b7b54061c7369d8807edecd9dbd0a19d13"
    $a3="7defdb045e7e527c20174f1ad436860d9f8ee58f22178401553c6b5ef38e5218"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}