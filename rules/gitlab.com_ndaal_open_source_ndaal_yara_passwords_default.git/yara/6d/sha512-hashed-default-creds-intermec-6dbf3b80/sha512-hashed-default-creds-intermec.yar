rule sha512_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
    $a1="bf076296b675c1dccd2616e8f3312fa2c3de539d7e1278bededbb09e008206e33f3c8b20c77fa323aea9636e03634847c142d7cbbb37263bd29dee98da568120"
condition:
    ($a0 and $a1)
}