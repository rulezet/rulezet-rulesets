rule mysql323_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5816bd6724cd8469"
    $a1="58f7ee435f925abe"
    $a2="2114daf16367cf54"
    $a3="58f7ee435f925abe"
    $a4="286ea95202a68590"
    $a5="58f7ee435f925abe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}