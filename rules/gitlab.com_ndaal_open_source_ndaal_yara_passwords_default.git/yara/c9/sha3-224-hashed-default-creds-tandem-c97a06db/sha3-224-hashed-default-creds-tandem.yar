rule sha3_224_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
    $a1="2f47dbe417bb97c7fbeb4f1114d41edc48dd56b99ac203a7a642701a"
condition:
    ($a0 and $a1)
}