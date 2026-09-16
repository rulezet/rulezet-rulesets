rule mysql41_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*FA1264335F473FF5E54E013CF848864DC5981B24"
    $a3="*CEB13241ECCA834930B3FAA5385F34D0C1DD6634"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*8CC79B5FDA8D438648AE41FD2B305F0967FF0F44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}