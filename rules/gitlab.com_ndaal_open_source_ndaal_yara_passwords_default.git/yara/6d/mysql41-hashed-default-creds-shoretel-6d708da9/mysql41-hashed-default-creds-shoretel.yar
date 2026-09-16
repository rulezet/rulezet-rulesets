rule mysql41_hashed_default_creds_shoretel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shoretel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*7ACE763ED393514FE0C162B93996ECD195FFC4F5"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*6D45FD76D5E9C6A404E39C25106A7F032659ACB8"
    $a3="*D89A99106002D77C1D327FC41E005919505638B0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}