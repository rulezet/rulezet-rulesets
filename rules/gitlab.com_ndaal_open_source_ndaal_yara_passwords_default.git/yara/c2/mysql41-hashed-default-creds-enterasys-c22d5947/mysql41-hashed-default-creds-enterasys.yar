rule mysql41_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5A663994E26D658F8E7972F1AE5EFEAEE733AF7F"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*28CEBF99A3C7C01D020A9ED46E52E8A6632177E6"
    $a3="*F2F68D0BB27A773C1D944270E5FAFED515A3FA40"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}