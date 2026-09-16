rule mysql41_hashed_default_creds_mysql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*A3A526C816BEF5B8F195A3C5C4E610CE595B58A5"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*D0A5E73319EDA9F32DE1E25FDB59432DEDD354B1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}