rule mysql41_hashed_default_creds_kti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kti."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a1="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a2="*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}