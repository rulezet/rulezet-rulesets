rule sha256_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d84719abfe8d1df26ea8413cadbc63c412dd369d94a952f4ce92156a5321cc3"
    $a1="9d84719abfe8d1df26ea8413cadbc63c412dd369d94a952f4ce92156a5321cc3"
condition:
    ($a0 and $a1)
}