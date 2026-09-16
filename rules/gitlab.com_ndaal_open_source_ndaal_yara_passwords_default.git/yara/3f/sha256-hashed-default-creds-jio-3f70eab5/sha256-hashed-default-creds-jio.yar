rule sha256_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="432e9eb5f5b24ab931be050256c0f3dc8296e1b41b08fd91201cae9dc7a554b5"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a3="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}