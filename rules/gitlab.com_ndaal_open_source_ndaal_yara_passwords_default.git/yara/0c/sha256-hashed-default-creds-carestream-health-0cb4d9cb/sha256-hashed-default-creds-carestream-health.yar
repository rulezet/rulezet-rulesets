rule sha256_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a61d32b8ba90c5dd928e2a66d9ef5f686ebd1ff1cb7dd52f28c9da99e8fcceb"
    $a1="b4c51a6b12d78e48ea6cfe0702848b5d8e925985766fe7632a89993c09cf9f09"
    $a2="7a61d32b8ba90c5dd928e2a66d9ef5f686ebd1ff1cb7dd52f28c9da99e8fcceb"
    $a3="d140261e9173539cb2e60dbf1b594dfb9d05a09e925d6f54c0fe932c45be8dd2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}