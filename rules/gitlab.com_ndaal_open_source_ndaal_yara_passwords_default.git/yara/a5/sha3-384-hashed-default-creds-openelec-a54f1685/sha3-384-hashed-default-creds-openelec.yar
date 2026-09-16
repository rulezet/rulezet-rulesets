rule sha3_384_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c035798e4887db35dcf7fadeef55d6e42b298572856e565f6c94e1892f03c0d09ab118b278b595dc8597429bef7b7adb"
    $a1="d7dbff373926d907b4027238e58cd9f3133c5b49fd6f533d21f8a2e14abf757982cdb82eaac87e6f7e8310cb2b4ad57d"
condition:
    ($a0 and $a1)
}