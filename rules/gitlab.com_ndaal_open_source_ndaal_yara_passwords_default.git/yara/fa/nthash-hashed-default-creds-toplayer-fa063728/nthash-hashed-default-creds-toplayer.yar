rule nthash_hashed_default_creds_toplayer
{
    meta:
        id = "6jZZEUyhTTFpqPfu8RELcv"
        fingerprint = "50c281d8000fb4d49d39d201ec8e92dd8665484bdbf3a6d116f9fed603883724"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bf69333f259134321cc0a4e058cd40dd"
    $a1="2e17ae860ac9d678cd6b9c16dbba6006"
condition:
    ($a0 and $a1)
}