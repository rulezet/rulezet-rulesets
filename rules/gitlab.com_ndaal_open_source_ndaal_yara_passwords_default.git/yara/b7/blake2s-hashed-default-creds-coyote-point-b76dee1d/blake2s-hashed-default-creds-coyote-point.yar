rule blake2s_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18c2d0d6f5c30c2e025d136c68db5b92cd5cd4a5d9b40d4a4645da448410d41b"
    $a1="5d719fdff7350eac86c95884a76e7082a8785bbd5014118bbcb87adfc9756daa"
condition:
    ($a0 and $a1)
}