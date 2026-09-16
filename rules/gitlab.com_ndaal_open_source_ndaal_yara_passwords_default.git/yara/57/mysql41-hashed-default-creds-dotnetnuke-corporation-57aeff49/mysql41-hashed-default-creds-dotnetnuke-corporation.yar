rule mysql41_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2DC5191575F77F0B5A12DB6DAB7F1F918E3B542E"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*94FFAC0D81E4746B99DA1C3490C2D05207157823"
    $a3="*484B60B6F4F97FAE548978748359C3A0DD72DBBD"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}