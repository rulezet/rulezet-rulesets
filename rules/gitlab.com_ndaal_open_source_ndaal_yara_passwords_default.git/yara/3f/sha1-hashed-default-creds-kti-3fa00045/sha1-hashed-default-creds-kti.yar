rule sha1_hashed_default_creds_kti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kti."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a1="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a2="40bd001563085fc35165329ea1ff5c5ecbdbbeef"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}