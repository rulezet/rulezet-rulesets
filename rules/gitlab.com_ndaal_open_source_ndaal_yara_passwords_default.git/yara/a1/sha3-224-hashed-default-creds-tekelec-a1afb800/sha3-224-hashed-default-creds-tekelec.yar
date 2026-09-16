rule sha3_224_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d02a75815c14cbbf88eb9061380adffd14dc907032ea27ffa6bb187c"
    $a1="d02a75815c14cbbf88eb9061380adffd14dc907032ea27ffa6bb187c"
condition:
    ($a0 and $a1)
}