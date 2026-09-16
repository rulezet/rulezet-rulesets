rule blake2s_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75c856f8dafea2efdd289bd1899bb0ead16d3046755cadf0bd7b4d5ed84004e4"
    $a1="cd6174dabe77c06c69b54be3835b567510f8864605b6b1a5498a4c9ca211faaa"
condition:
    ($a0 and $a1)
}