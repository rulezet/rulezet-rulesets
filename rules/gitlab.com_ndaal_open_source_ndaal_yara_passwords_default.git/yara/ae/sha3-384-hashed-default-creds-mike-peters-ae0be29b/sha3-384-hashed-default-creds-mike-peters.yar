rule sha3_384_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e974aa87cd12edc23db032a6482a8db971d800beb2ddc1233fe77d68efbf7f7ccc31f9d28929390956c04ed79caa97a7"
    $a1="0b5fe5ddf86d2ba1753ceb31abeb735cc93b8deaf9244eb68f11fce42c21c56e082ab87d78f9cd8c4e73b708696a8c0f"
condition:
    ($a0 and $a1)
}