rule sha256_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="119c9ae6f9ca741bd0a76f87fba0b22cab5413187afb2906aa2875c38e213603"
    $a1="119c9ae6f9ca741bd0a76f87fba0b22cab5413187afb2906aa2875c38e213603"
condition:
    ($a0 and $a1)
}