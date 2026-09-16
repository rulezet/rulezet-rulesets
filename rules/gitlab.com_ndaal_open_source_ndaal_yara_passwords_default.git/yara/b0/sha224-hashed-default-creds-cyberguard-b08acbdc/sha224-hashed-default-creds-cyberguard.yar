rule sha224_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00a907bed6ab2911537c2d24eb3cab299679a29b4cbcb25757adfb90"
    $a1="00a907bed6ab2911537c2d24eb3cab299679a29b4cbcb25757adfb90"
condition:
    ($a0 and $a1)
}