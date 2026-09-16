rule sha224_hashed_default_creds_fujitsu_siemens
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fujitsu_siemens."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80b7bfbafd6f1e45393c72bc0351c9a6fc8258c02d559ce24b37656f"
    $a1="879f72dd8c12cb2e03273925d27d23a21354668e9917048b17fbcb7b"
condition:
    ($a0 and $a1)
}