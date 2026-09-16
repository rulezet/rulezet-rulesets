rule sha224_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e19deae1228dde507418d1f8e7b68f7763bcbf7ffdc52b55791c7dce"
    $a1="f1b54a4843d22631aba8fa60caf2e8dcb6a3ef9f613439db0b9ab6b2"
condition:
    ($a0 and $a1)
}