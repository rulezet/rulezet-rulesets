rule mysql41_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*11D763029A736773290BC11E6B2857A7EB11813B"
    $a1="*11D763029A736773290BC11E6B2857A7EB11813B"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*432DADB80863E758A32913E510F74D01A605B00B"
    $a5="*432DADB80863E758A32913E510F74D01A605B00B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}