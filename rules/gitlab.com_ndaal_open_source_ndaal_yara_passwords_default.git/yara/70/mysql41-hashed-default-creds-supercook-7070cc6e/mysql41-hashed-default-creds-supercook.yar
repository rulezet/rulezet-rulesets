rule mysql41_hashed_default_creds_supercook
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supercook."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*289E2E4C79ABEB644F126B7BE5B1BADC56D7D093"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
    $a3="*F85A86E6F55A370C1A115F696A9AD71A7869DB81"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}