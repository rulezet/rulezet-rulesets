rule mysql323_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73011bb64451ddd0"
    $a1="737fdc5d4f98fcb6"
    $a2="34873a66410f7bba"
    $a3="7d92079d48cb5039"
    $a4="75d6df4260c9b4f5"
    $a5="7870c0597c159967"
    $a6="21648e081ab3a088"
    $a7="25dd806b1ced7723"
    $a8="172f2b192cc52a72"
    $a9="172f2b192cc52a72"
    $a10="6ceb598953410665"
    $a11="6ceb598953410665"
    $a12="6d26a7f521e403e7"
    $a13="6d26a7f521e403e7"
    $a14="2186976746a75f6b"
    $a15="2186976746a75f6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}