rule mysql41_hashed_default_creds_microcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microcom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*22E1EF6F5BEF67A29C76F84CC091947307B69295"
    $a1="*576EE5B74C20E68F2A5A240F3E408E6DE43DD73F"
    $a2="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a7="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}