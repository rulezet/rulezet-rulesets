rule mysql41_hashed_default_creds_conexant
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conexant."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*B900002777FF8BE6A1A5BF1362FFDBB7E4055D21"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*87E43F7A3F933854597D380F5E73E5E39AFB857B"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}