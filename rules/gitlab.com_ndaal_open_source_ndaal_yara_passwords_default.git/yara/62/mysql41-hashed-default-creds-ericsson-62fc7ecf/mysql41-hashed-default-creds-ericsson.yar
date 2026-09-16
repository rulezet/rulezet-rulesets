rule mysql41_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EA65B77CA9F825F8D7FCDF0D5AE96993216972C2"
    $a1="*EA65B77CA9F825F8D7FCDF0D5AE96993216972C2"
    $a2="*69156C3775BC63A03BDF56AD0B48E2BE5DF601DD"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*094B6D391FDDAA4DD6F16725D9E7E2B7E7BE81F7"
    $a5="*4C2D3F337EC616F0757FC3FB16A2793EBF1E949D"
    $a6="*751F84EF302237A40832D400DF60EB981B16541E"
    $a7="*751F84EF302237A40832D400DF60EB981B16541E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}