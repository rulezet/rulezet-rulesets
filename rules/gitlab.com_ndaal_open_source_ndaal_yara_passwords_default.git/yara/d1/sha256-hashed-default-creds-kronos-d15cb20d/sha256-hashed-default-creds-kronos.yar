rule sha256_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ec0fd2c691694d1a66b4fb1aab926cf702d4fc8e0337560f52a735c6c2001c3e"
    $a1="9f132b053488478489310e498069a7c6dd58e285fd1f7b18ddab98a5129643b9"
condition:
    ($a0 and $a1)
}