rule mysql41_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a1="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a2="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*7696A148A42BA0F83F31613B2324447265D5A2ED"
    $a5="*A7AE60C580DE2418DC45F395674BE789771A530F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}