rule mysql41_hashed_default_creds_ruckus_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ruckus_wireless."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*8A3C48B214207AC133B8A5C1416FC0924554C5F6"
    $a1="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*8A3C48B214207AC133B8A5C1416FC0924554C5F6"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}