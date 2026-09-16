rule mysql41_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B22EF46BF10066F7469067D68FB79A6B3CDF8570"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*0BCCF19E08FB4060C8927C687823904E2CF92D75"
    $a3="*0BCCF19E08FB4060C8927C687823904E2CF92D75"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}