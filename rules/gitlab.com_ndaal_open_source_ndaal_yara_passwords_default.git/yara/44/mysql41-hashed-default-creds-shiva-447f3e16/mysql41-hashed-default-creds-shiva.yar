rule mysql41_hashed_default_creds_shiva
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shiva."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6B4F89A54E2D27ECD7E8DA05B4AB8FD9D1D8B119"
    $a1="*6B4F89A54E2D27ECD7E8DA05B4AB8FD9D1D8B119"
    $a2="*6B4F89A54E2D27ECD7E8DA05B4AB8FD9D1D8B119"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}