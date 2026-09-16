rule mysql41_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*020E337237B759E9B82CA7CDF61A97289BC452AD"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*E9F5FFA5D1DE7D540B4081280B903BF5335D3AC2"
    $a3="*0B0A27832C339662F96E0238AD92FCBCB992A7EA"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}