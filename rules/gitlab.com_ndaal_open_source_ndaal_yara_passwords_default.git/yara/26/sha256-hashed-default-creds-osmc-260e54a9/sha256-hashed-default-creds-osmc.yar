rule sha256_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4ebf8e6c66f6a8f14f9d655c8fa7db06e4dcea9dcfd3eaa81843e44e4f78c34"
    $a1="c4ebf8e6c66f6a8f14f9d655c8fa7db06e4dcea9dcfd3eaa81843e44e4f78c34"
condition:
    ($a0 and $a1)
}