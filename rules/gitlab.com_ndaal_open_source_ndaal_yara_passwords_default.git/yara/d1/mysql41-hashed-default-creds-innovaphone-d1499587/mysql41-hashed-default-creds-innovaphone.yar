rule mysql41_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*332AFFA277E69DFD6ACF8C290D2F2443BB4DF247"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*1126687001B192EAA9862829B7DF450268BC2C4E"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*A2CDDCE7F93E015F831D62ECDD3D729AC4DF80ED"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*B095D61636ABDEB80AD869A39CF80B1D62869E16"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*36EB1EB015C8857C3008760DF7C6BE1368CA80B7"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}