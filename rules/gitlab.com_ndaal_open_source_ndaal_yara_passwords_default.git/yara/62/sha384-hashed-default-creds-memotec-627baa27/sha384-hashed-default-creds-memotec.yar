rule sha384_hashed_default_creds_memotec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for memotec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cbe8fc7bd50b262e822d039459015cb5f4fc3255a86d3fd14c81140153dc714b24bb7a2e2159842415aba43e63b3189"
    $a1="e4f142111a4f88b6b4645cd82e3438fc501b1e8337093914024aacffeb7dd6324b38784398a830b7663bdd82ba124ba9"
condition:
    ($a0 and $a1)
}