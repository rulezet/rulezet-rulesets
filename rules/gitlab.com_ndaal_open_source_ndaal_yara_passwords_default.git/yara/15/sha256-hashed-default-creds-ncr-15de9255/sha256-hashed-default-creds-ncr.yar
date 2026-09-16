rule sha256_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6339b64898640df06d70bc408ab27e54de6f9232ce61beb7f8fb24fef016387c"
    $a1="6339b64898640df06d70bc408ab27e54de6f9232ce61beb7f8fb24fef016387c"
condition:
    ($a0 and $a1)
}