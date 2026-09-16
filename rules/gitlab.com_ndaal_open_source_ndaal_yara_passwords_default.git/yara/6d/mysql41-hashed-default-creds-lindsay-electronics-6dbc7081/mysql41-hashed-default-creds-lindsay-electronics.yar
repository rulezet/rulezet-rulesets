rule mysql41_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*19044D9849273EBC9E1F98B98E1EE9F1B8CA914F"
    $a1="*81A52AB76BBAB3CCC39A8E901EAD6DDE36816800"
    $a2="*19044D9849273EBC9E1F98B98E1EE9F1B8CA914F"
    $a3="*19044D9849273EBC9E1F98B98E1EE9F1B8CA914F"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}