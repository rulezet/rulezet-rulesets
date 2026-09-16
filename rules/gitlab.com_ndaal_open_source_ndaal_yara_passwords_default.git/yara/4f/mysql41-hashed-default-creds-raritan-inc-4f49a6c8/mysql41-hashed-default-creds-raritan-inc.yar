rule mysql41_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*80515436B847E9D9A263148CDC1362D484E93DBB"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*80515436B847E9D9A263148CDC1362D484E93DBB"
    $a3="*42710275B0BF9F0CDFD3947DDF9D0278E913A53F"
    $a4="*6244517EAB99157322B5B9C3EBBB4307D8659471"
    $a5="*9D087988F4F0B6B6D2863A23E54B388621DE8944"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}