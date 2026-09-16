rule sha3_224_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5825fe316a898a5f26d2b067c32982a147de4639896d9c62293bc29a"
    $a1="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a2="f8f527fdd5e917fa17f83a42411dcbe04e6e7c95d4bcd8797eadeedc"
    $a3="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}