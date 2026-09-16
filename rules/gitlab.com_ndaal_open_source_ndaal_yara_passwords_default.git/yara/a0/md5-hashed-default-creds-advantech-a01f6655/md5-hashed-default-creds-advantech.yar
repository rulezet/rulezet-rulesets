rule md5_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="37d2980212c5048ad9e14dbaa8073d7b"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="dd4b21e9ef71e1291183a46b913ae6f2"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="dd4b21e9ef71e1291183a46b913ae6f2"
    $a7="fa03eb688ad8aa1db593d33dabd89bad"
    $a8="dd4b21e9ef71e1291183a46b913ae6f2"
    $a9="e3afed0047b08059d0fada10f400c1e5"
    $a10="dd4b21e9ef71e1291183a46b913ae6f2"
    $a11="8f9bfe9d1345237cb3b2b205864da075"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}