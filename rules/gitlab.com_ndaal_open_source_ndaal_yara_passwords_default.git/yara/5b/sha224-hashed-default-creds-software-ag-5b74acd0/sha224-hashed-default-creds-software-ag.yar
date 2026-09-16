rule sha224_hashed_default_creds_software_ag
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for software_ag."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="879f72dd8c12cb2e03273925d27d23a21354668e9917048b17fbcb7b"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
condition:
    ($a0 and $a1)
}