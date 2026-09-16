rule md5_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="e3afed0047b08059d0fada10f400c1e5"
    $a2="1785414fbed7392a3e894f930929cbd7"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="1785414fbed7392a3e894f930929cbd7"
    $a5="1785414fbed7392a3e894f930929cbd7"
    $a6="4eb1a7acdc0334cb2239e8308ed56cfe"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="35b3db8059fd92c49862704b36410ccf"
    $a9="a6715e5ac80051a0205fe50a22f74c44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}