rule sha3_224_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7dbd92d14482ba4f9d0ed23691a4785ace8b2c693b250d726205abc"
    $a1="5122338bd461aecad5e9cd8266c965d6068c3a17e6283d041e4d4627"
    $a2="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
    $a3="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}