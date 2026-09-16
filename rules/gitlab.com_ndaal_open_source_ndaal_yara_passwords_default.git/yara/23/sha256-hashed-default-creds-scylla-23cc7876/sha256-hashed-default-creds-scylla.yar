rule sha256_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1c6127b16ff422bfa09b98334abe44c5f88327e2a2185a2fe00ce26cdcf0075"
    $a1="f1c6127b16ff422bfa09b98334abe44c5f88327e2a2185a2fe00ce26cdcf0075"
condition:
    ($a0 and $a1)
}