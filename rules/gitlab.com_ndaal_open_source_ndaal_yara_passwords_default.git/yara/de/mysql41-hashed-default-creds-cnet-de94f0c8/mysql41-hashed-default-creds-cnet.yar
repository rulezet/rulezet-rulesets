rule mysql41_hashed_default_creds_cnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cnet."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a5="*D89A99106002D77C1D327FC41E005919505638B0"
    $a6="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a7="*D89A99106002D77C1D327FC41E005919505638B0"
    $a8="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}