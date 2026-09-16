rule mysql41_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*196BDEDE2AE4F84CA44C47D54D78478C7E2BD7B7"
    $a1="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*FC4C8052E3C11C2C1FBB16180EFFFC36869B177E"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*922A4B420903CAD4E7FC56A23122AB927E051FE3"
    $a7="*15E5CE8BD40B2370371D57F7DC5E7A48066EE26B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}