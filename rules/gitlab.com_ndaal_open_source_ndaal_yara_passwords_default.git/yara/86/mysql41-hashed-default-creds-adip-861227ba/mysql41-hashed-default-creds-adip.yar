rule mysql41_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*0EA656E38F2CDE422AB4A16C2F193961B729DFA4"
    $a2="*292B68EE8B8EFB7759627E76EE71A8FC4123D7D0"
    $a3="*0EA656E38F2CDE422AB4A16C2F193961B729DFA4"
    $a4="*CF5C2EE2DF6727041F2283BAA429F371843D466C"
    $a5="*0EA656E38F2CDE422AB4A16C2F193961B729DFA4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}