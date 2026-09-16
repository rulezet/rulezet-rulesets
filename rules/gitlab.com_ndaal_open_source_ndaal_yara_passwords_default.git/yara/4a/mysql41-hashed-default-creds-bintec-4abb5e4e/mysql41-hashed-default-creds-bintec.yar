rule mysql41_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*CCB1BB28F88A894CB7C4D77D376A6C37ED6328D3"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A84C03F4B01FED6870AE4A0C7E0DF31C7D9DEAB5"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*64A2B7B816254030E6A31ED55D535B33A0659CCB"
    $a5="*D89A99106002D77C1D327FC41E005919505638B0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}