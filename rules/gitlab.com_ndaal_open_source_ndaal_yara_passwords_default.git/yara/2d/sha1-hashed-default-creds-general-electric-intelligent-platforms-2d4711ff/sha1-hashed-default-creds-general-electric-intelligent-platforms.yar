rule sha1_hashed_default_creds_general_electric_intelligent_platforms
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_intelligent_platforms."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a3="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}