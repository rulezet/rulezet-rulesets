rule sha384_hashed_default_creds_robigvqubqt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for robigvqubqt."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b246be666938724f021773a2457a83c89a88067d7c2648ea7d50d8725f254a52fe3a07364a31308288caa27aa26e1a8"
    $a1="30538160cae262d9dc805adc9b740d01ded8eb6e1a0d5f0e854614b5f3fa156d984e94eaa41f42ce2702d480e5638332"
condition:
    ($a0 and $a1)
}