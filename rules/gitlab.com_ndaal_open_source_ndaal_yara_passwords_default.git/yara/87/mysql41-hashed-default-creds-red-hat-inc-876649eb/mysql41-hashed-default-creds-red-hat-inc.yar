rule mysql41_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
    $a3="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
    $a4="*3FBEFEC33FD8E842761B011670846D73057E67BE"
    $a5="*A9B0A1E19CBBD9CB19DBDD2FBAC9F89CC652E3EF"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}