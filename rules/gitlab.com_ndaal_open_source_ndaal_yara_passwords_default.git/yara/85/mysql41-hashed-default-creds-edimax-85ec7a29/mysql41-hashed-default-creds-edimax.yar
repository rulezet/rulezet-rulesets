rule mysql41_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*6F116B764650FF0E7363CB5D7FFEF458B10C5FC4"
    $a7="*DF8F7928BF0DF7336DAEC8248C8E1EB6163EA26A"
    $a8="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a10="*4D41739F7DA407944F6998B51CFE813CAD04E855"
    $a11="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a12="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a13="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}