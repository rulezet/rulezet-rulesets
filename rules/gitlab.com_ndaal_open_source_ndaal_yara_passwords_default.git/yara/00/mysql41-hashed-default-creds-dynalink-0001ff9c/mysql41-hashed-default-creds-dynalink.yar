rule mysql41_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*85BB02300F877EB061967510E83F68B1A7325252"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*0CD1D2A6E8875E160C88101983AF21647A091E03"
    $a5="*7C81C70F52A878310DDF36856C5B0830583536DF"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}