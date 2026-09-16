rule mysql41_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F7A763809A6F09611399B55D3778B91079DE488D"
    $a1="*956D20503E7318E7F7F68CA7AC24B3CDFFE3D0A2"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*C91474C93A7A272091D89920625F9C1749E6567F"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*050F46D65B660795AB12D8E1FF4B4143B6E080C4"
    $a7="*050F46D65B660795AB12D8E1FF4B4143B6E080C4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}