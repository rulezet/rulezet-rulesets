rule sha256_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac966e97f37d15130e47307565a9f0e86a69186b02b1a44798207704669aaf5e"
    $a1="ca5d4525f3e86ac4b688a47207e56c6b01265a1884272a6282aa4c09b712c7a6"
condition:
    ($a0 and $a1)
}