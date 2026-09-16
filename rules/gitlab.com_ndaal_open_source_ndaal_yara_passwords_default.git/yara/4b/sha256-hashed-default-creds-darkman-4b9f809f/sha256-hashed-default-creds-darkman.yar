rule sha256_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d56e5d6fad2da9f75de4a0fa70e8f88c77445c4cccf840865f3326abf8191a5a"
    $a1="d56e5d6fad2da9f75de4a0fa70e8f88c77445c4cccf840865f3326abf8191a5a"
condition:
    ($a0 and $a1)
}