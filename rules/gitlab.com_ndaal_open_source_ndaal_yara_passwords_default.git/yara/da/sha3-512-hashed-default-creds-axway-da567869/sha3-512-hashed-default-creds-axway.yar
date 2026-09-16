rule sha3_512_hashed_default_creds_axway
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for axway."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
condition:
    ($a0 and $a1)
}