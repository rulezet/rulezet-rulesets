rule md5_hashed_default_creds_moxa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for moxa."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63a9f0ea7bb98050796b649e85481845"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}