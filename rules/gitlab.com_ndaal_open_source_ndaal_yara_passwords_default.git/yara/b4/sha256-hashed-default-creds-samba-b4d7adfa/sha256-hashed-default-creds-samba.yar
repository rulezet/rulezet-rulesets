rule sha256_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b505597daa736f13c2910c260e8deb1af3b20ffe375eb5e01a003e92f541db9"
    $a1="2b505597daa736f13c2910c260e8deb1af3b20ffe375eb5e01a003e92f541db9"
condition:
    ($a0 and $a1)
}