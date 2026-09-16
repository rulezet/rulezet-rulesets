rule md5_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a731a984ad01873cafab2ba10449b9a"
    $a1="19aa0026f6ad6a0cb78c87f953da68fc"
    $a2="0192023a7bbd73250516f069df18b500"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="cddaddc65f8ad0714c7f63031eef60f1"
    $a5="4111cb7b732b45c2a5a71eae294b4e1c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}