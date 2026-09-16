rule mysql41_hashed_default_creds_deif
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deif."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3C08CC2421CD36E011ADF0B432A5669975D7DA2F"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}