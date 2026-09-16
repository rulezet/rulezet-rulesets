rule sha256_hashed_default_creds_system_32
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
    $a1="1e142e6277b12b7e1110478a24caee8f006a9349e86970c890203d6266209463"
condition:
    ($a0 and $a1)
}