rule mysql41_hashed_default_creds_draytek
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for draytek."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a3="*C35BBFECEC69D0125132AE61F4C6339CFD701A11"
    $a4="*A4B6157319038724E3560894F7F932C8886EBFCF"
    $a5="*92A1A23E74A0B83FE1CFD343BF09A414A39A9112"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}