rule sha512_hashed_default_creds_3m
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 3m."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
    $a1="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
condition:
    ($a0 and $a1)
}