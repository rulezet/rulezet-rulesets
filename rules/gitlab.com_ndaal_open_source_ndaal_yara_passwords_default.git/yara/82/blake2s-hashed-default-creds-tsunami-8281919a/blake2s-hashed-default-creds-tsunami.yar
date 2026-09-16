rule blake2s_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c274bf0354e35825ec32b0e7ca3d00f8e4d2a7770c84897fc51694556c6e6a6"
    $a1="0c274bf0354e35825ec32b0e7ca3d00f8e4d2a7770c84897fc51694556c6e6a6"
condition:
    ($a0 and $a1)
}