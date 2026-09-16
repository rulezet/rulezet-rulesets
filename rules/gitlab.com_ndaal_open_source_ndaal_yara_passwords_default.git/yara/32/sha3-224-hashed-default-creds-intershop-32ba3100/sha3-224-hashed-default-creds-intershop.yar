rule sha3_224_hashed_default_creds_intershop
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intershop."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85ce017ed00701d9318be5d86966e7caf56d38005849436a8c6cf729"
    $a1="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
condition:
    ($a0 and $a1)
}