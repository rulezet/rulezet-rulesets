rule mysql41_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a3="*C261D162D699A1062FFA52AD73CC3F1BCE78FD63"
    $a4="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}