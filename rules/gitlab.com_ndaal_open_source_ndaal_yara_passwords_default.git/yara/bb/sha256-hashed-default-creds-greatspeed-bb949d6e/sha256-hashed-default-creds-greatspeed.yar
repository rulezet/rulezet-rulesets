rule sha256_hashed_default_creds_greatspeed
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for greatspeed."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da677aac89d82d9f881ffdb6c64617e8e017bb7cfe42f7db826074b40bc5e9ae"
    $a1="dcf803280302c60456047893d5d1014bdedb3eab7bc5c920770ac00c9883a168"
    $a2="7577bf4f5683bf6cc6ce6324381b36449961897cc37140d2171d5953244fb6e5"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}