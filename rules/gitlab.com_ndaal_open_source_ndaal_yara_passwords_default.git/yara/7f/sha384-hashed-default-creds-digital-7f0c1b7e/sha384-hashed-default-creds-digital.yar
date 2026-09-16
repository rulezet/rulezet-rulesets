rule sha384_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a843ab7a61d79f6e16f673a5bd702c737be452b80fc92f912b0e608f4797d838e96ae673c13546da077d1aec5ae12954"
    $a1="d063457705d66d6f016e4cdd747db3af8d70ebfd36badd63de6c8ca4a9d8bfb5d874e7fbd750aa804dcaddae7eeef51e"
condition:
    ($a0 and $a1)
}