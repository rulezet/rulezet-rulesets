rule mysql41_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*497F081B3750057FE652584E2611798B53DB6389"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*497F081B3750057FE652584E2611798B53DB6389"
    $a4="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a5="*F5AB3475E4D0309381498567B7C7A270ADED2652"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}