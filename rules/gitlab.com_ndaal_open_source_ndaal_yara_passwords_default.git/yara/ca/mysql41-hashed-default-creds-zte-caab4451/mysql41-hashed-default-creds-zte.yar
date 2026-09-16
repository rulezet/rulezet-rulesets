rule mysql41_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*112FB8BF2207F7DF5F9BE855EBD8E38180CE6F6D"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*E7CDE8E34F73D02760C9A0C1CCCB119DC0AA187F"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a5="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a6="*6229E5FE22F86C1DE4C6847D8A76F1C31A7CFA15"
    $a7="*FA8ABDA23E9E13C815145E381C45FE1129B1B0B2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}