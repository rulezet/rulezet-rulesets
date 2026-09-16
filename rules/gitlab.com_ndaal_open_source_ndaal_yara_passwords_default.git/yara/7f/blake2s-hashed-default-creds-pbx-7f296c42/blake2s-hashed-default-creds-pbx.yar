rule blake2s_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4ee5c4e0ee0bb814b56556defeb5844c00b57d788daef6c55b9be301f31f18d"
    $a1="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
condition:
    ($a0 and $a1)
}