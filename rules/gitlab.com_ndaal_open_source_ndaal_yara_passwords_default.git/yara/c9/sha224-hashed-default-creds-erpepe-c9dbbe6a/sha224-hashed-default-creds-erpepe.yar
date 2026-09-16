rule sha224_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="489805f9a240bb910b9ca551030c4e5c93f71b241739e07a3b81f218"
    $a1="bbfb8496eaffb6488ae20d68208f6e5b212ab477d79d9b56a1005670"
condition:
    ($a0 and $a1)
}