rule sha1_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f227ea565a219561e253bdfaddbbfba4f7ced3d"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="1a9b9508b6003b68ddfe03a9c8cbc4bd4388339b"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="fea7f657f56a2a448da7d4b535ee5e279caf3d9a"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="3f227ea565a219561e253bdfaddbbfba4f7ced3d"
    $a9="7b21848ac9af35be0ddb2d6b9fc3851934db8420"
    $a10="011c945f30ce2cbafc452f39840f025693339c42"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="20946a5e90706436fc6fd23a8e4c2ae562401725"
    $a13="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a14="6061863623f806d7db7ac8fa8f9e370bbbe9c095"
    $a15="21fbf8d2e95777b9e93ddf46afc29453f82335ac"
    $a16="2fc7f1452374b6e341d67717f032abbe0da0f4a6"
    $a17="e2c624e64d47fc281845dfc20c2c55f152c8c140"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}