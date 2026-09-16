rule sha384_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64c9b548de7347c89fe02e858c0d26fff14b95da8f4ed74c3159446d3748d98eaf7a8a44b7a262a20a8112729b5dbe45"
    $a1="64c9b548de7347c89fe02e858c0d26fff14b95da8f4ed74c3159446d3748d98eaf7a8a44b7a262a20a8112729b5dbe45"
condition:
    ($a0 and $a1)
}