rule md5_hashed_default_creds_asus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asus."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="293c9ea246ff9985dc6f62a650f78986"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="edbd1c6d19454e4250c1545332a2405d"
    $a9="86f6330f3fade348d8e2cf87ef6868dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}