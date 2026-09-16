rule sha256_hashed_default_creds_ca_apm_team_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_apm_team_center_web."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a1="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
condition:
    ($a0 and $a1)
}