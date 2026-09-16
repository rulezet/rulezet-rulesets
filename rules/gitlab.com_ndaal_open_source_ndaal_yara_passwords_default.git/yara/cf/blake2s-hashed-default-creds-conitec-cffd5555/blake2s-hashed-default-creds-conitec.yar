rule blake2s_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e37fa5da241cd4bf8f408d6ede830a440c3ff97d61efa7d8fccc8473b64f1d06"
    $a1="acdbea4c52c7ce2f563c885fea8f74acaf981100729ef22715ac0ad78bac82ec"
condition:
    ($a0 and $a1)
}