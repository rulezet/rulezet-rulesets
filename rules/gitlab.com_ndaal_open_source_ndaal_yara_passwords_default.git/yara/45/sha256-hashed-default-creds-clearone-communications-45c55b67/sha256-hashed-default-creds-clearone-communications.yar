rule sha256_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54caafa49296ec47f1839e46980ed744804fb7b23264bc6801e03af643c5fbf1"
    $a1="d0ea4a011db775ff3782b0e6dee0c25907909716e4b162d2054520615065464a"
    $a2="c563c209d627c4c5585b8bc6fe39521c27b545be63927fa283df66ff03abf315"
    $a3="208e992f2d602142a01d0663211b6c27d62a20a7c3f9aa3c9b476b4e7ad28953"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}