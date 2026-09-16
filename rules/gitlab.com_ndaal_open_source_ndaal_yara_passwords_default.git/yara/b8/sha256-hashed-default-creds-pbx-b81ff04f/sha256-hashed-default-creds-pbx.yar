rule sha256_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="042f83bc95908fb79c847ca651ceefdab5be1274df956efa0a67b427f68d7d9d"
    $a1="fe9bbd400bb6cb314531e3462507661401959afc69aae96bc6aec2c213b83bc1"
condition:
    ($a0 and $a1)
}