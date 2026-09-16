rule nthash_hashed_default_creds_videoiq_web
{
    meta:
        id = "741kJDlseARbWGC9F55LPZ"
        fingerprint = "9fc937575a7f4debdda2156af21d29149ec489f4b929269a9b1e2d72b0628d40"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for videoiq_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b547e99ae0f3800915f05cb7a152da11"
    $a1="b547e99ae0f3800915f05cb7a152da11"
condition:
    ($a0 and $a1)
}