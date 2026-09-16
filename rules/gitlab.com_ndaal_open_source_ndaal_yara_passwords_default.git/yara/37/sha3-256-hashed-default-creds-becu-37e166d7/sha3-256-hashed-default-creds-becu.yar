rule sha3_256_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d85a634098f37c08551692653735f515c0c668da8ecdb7299a3c481256ee9012"
    $a1="e1e429a92357a8522f6e8d63a1ec3f7f20b63399063eb7d24f2e8b5ada5d0a56"
condition:
    ($a0 and $a1)
}