rule mysql41_hashed_default_creds_netopia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netopia."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FFA2B3BD57A41AF0F2E003244B7B5C6554799217"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*1917EAF750491AEA862B446E80EB2B73925B630A"
    $a3="*1917EAF750491AEA862B446E80EB2B73925B630A"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}