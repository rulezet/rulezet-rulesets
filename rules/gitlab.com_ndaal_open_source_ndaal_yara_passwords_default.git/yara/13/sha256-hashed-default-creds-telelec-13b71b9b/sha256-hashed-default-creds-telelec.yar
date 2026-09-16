rule sha256_hashed_default_creds_telelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telelec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e73b48f750be953532c1d1757b5ba081e8a6b0408ea8b4e65ef1e65631a7da06"
    $a1="e73b48f750be953532c1d1757b5ba081e8a6b0408ea8b4e65ef1e65631a7da06"
condition:
    ($a0 and $a1)
}