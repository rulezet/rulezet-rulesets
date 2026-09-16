rule sha384_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a1="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
condition:
    ($a0 and $a1)
}