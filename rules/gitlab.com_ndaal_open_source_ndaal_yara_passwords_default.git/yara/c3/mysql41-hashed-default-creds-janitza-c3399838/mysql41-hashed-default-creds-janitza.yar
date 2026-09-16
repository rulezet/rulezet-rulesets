rule mysql41_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B0CBF6D5A63D2D662334EF2315B8226BE4EFD765"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*B0CBF6D5A63D2D662334EF2315B8226BE4EFD765"
    $a3="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a4="*F1D4243618BD51F1142C7CC6C8ED5DC49972F509"
    $a5="*2B75DFD0E67F95AAB941026706D7281F3750D9C0"
    $a6="*B0CBF6D5A63D2D662334EF2315B8226BE4EFD765"
    $a7="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}