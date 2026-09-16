rule sha1_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d6dd51fb8f76158f084629b37f94079a98df6fc"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="5d6dd51fb8f76158f084629b37f94079a98df6fc"
    $a3="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a4="9fc237feb3db61662a5666fea2fbcd0ce327bc8a"
    $a5="52128b06870ba981c1e894ddef21a5c004413a79"
    $a6="5d6dd51fb8f76158f084629b37f94079a98df6fc"
    $a7="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}