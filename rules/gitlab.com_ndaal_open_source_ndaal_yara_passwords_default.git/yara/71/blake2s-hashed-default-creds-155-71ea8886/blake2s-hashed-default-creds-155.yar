rule blake2s_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f70f0557c4f76d274cb79d700ab485d363f0b7722f5c5e94ce70c2b7cee1fc74"
    $a1="61b83c12ccabd0333a492ba2d826cbeae8d9b2febdc369da09614c29342a2bd1"
    $a2="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
    $a3="cebe32cdfd4b0014d09ee07bdb2f8816518d0599798bb30b9a303bc1c663af70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}