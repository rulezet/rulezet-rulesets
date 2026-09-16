rule sha256_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7df0cbb692fc1fd64f987a0548664a6a5e6ff09f7c55510aff3311b4ac034da"
    $a1="aa79f11221e25ddb870233c5ecb79eb1c341d1b67db1ba5273f68076982efee4"
    $a2="c2fa26d57cd69ed4cf86f1a9cf8f0232cc20b24387e3299aa267224722bd31ef"
    $a3="518b67e652531c5fe7e25d6b2c3b4ef6224e7d90da2091967dd47eb082b26a19"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}