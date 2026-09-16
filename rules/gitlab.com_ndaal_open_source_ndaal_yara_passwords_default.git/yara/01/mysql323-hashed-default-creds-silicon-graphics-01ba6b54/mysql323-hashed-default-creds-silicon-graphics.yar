rule mysql323_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fb19ab3555227d9"
    $a1="6fb19ab3555227d9"
    $a2="6d6608be5e6f7fa3"
    $a3="6d6608be5e6f7fa3"
    $a4="3c91bc542731520d"
    $a5="3c91bc542731520d"
    $a6="2a4dc9205bcc0ce6"
    $a7="2a4dc9205bcc0ce6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}