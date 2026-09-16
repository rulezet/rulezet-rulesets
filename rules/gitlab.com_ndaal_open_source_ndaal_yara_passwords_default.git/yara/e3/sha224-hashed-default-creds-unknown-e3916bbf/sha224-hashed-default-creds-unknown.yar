rule sha224_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecff67aea52a4dd9e96c5ae660a311d31229c96aa548b2ea9315627b"
    $a1="ecff67aea52a4dd9e96c5ae660a311d31229c96aa548b2ea9315627b"
    $a2="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a3="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a4="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
    $a5="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}