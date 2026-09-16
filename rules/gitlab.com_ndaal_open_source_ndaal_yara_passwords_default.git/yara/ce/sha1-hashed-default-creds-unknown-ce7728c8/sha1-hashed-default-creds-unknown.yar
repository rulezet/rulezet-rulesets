rule sha1_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f77516644a1d3a3084194cee97e8fae9d1c6af94"
    $a1="f77516644a1d3a3084194cee97e8fae9d1c6af94"
    $a2="fe96dd39756ac41b74283a9292652d366d73931f"
    $a3="fe96dd39756ac41b74283a9292652d366d73931f"
    $a4="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    $a5="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}