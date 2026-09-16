rule mysql323_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e6e591c65136986"
    $a1="58f7ee435f925abe"
    $a2="34873a66410f7bba"
    $a3="7d92079d48cb5039"
    $a4="34873a66410f7bba"
    $a5="6ceb598953410665"
    $a6="73011bb64451ddd0"
    $a7="737fdc5d4f98fcb6"
    $a8="172f2b192cc52a72"
    $a9="172f2b192cc52a72"
    $a10="75d6df4260c9b4f5"
    $a11="7870c0597c159967"
    $a12="6d26a7f521e403e7"
    $a13="6d26a7f521e403e7"
    $a14="21648e081ab3a088"
    $a15="25dd806b1ced7723"
    $a16="2186976746a75f6b"
    $a17="2186976746a75f6b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}