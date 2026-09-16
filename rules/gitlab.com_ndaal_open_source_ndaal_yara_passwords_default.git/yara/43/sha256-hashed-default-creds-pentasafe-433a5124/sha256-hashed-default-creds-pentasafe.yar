rule sha256_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191cfcb01608c78c79ec7930a94362371425cc160bdeb49514979bf0320c7c83"
    $a1="81a9cbcc4d2d6d67ca4fe9fc94b0951a053413bd35e5315c5adaf882f4071c10"
condition:
    ($a0 and $a1)
}