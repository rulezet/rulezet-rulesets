rule sha256_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a1="b5a9716fcd63f4a279e2f6df8f6de89dce75ff38fad8c7e04ebb2d8e2227e2eb"
    $a2="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
    $a3="737f62617487a729b41b1f8b53f432f1551d3f2bd5124b016c7c0ecc69c46a80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}