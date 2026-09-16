rule mysql41_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
    $a1="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
    $a2="*3FBEFEC33FD8E842761B011670846D73057E67BE"
    $a3="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}