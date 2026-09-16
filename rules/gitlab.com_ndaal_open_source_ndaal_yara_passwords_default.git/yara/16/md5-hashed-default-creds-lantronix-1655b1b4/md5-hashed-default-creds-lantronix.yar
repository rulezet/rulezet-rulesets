rule md5_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54b53072540eeeb8f8e9343e71f28176"
    $a1="100b8cad7cf2a56f6df78f171f97a1ec"
    $a2="7a95bf926a0333f57705aeac07a362a2"
    $a3="48a365b4ce1e322a55ae9017f3daf0c0"
    $a4="9df3b01c60df20d13843841ff0d4482c"
    $a5="d56b699830e77ba53855679cb1d252da"
    $a6="7a95bf926a0333f57705aeac07a362a2"
    $a7="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}