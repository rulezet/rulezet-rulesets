rule sha224_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2da0a433943dbe79eca6489b23172882b1bb4f1ed7cc2d6c080b9ea9"
    $a1="2da0a433943dbe79eca6489b23172882b1bb4f1ed7cc2d6c080b9ea9"
condition:
    ($a0 and $a1)
}