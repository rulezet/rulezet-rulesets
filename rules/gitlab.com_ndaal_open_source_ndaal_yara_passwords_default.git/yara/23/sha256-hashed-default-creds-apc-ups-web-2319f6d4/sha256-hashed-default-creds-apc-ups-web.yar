rule sha256_hashed_default_creds_apc_ups_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
    $a1="a3ab747d76de03ff13b83c41df689d51fedb1d2836acae0489732d7da5cfc321"
condition:
    ($a0 and $a1)
}