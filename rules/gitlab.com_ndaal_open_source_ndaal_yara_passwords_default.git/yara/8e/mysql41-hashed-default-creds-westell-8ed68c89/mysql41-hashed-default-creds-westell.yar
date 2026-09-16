rule mysql41_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*668425423DB5193AF921380129F465A6425216D0"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*D8A4E765962CF7B9CC4526B9B672AE85B0CC00FE"
    $a3="*914D370F3A73E84E6F264C9BD6671714F3B81F95"
    $a4="*9FAE6570647C8B5C9F048BAD065D16C96893CD99"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}