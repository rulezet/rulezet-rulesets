rule sha3_256_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d57cd3911fea06ea5216199ebe00f719dfc32a7bf19923adeea5e1853d191c58"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="e4cd7fdf87ca2d2221f8a89496151e2a15199ba43960a944d6485b6eb46e7750"
    $a3="1bb00f682e1b26ab9e36ee7f9f874947bc00b5926c69451a22dc99fe8cfd21c6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}