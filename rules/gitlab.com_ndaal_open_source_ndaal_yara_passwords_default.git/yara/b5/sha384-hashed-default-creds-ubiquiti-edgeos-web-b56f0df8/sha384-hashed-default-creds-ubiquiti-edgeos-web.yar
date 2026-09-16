rule sha384_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
    $a1="dfa6565e08c58600772ea633020fbff6f438eb361b8326473e01f56e37b35e58d5457dc2af808efc30b633ee154453fd"
condition:
    ($a0 and $a1)
}