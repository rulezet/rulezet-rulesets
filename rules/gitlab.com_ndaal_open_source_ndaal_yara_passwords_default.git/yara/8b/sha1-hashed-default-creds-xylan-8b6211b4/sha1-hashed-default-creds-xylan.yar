rule sha1_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="01ba7992f85de477e8e630428eb5ed14769f9155"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="01ba7992f85de477e8e630428eb5ed14769f9155"
    $a5="529a2169843d649acaf9b41df60db6d69af1e991"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}