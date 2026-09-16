rule mysql41_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*E8F56377E0C5ED5E8841B16BEA90B9E0934D84DD"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*E8F56377E0C5ED5E8841B16BEA90B9E0934D84DD"
    $a5="*9B1D9D3B18004627ABDAE819BFCAADBD191FA58A"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}