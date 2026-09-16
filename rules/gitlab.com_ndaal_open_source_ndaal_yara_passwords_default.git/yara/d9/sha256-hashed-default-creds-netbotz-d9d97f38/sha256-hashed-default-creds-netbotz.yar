rule sha256_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="56ea8a8c7bb638399b7fece5e35e9e2a68933d021f1ac153dcf3fa448c4a2238"
    $a1="56ea8a8c7bb638399b7fece5e35e9e2a68933d021f1ac153dcf3fa448c4a2238"
condition:
    ($a0 and $a1)
}