rule sha1_hashed_default_creds_sun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="fa9beb99e4029ad5a6615399e7bbae21356086b3"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="f7a84e1338146bbf4b25a27d14b138848c991fff"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="cbcbc77f56a31cdcf98d7b7315e647dd21ceb8e9"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
    $a9="793d0520344d4e35ae49bc18fd51c9131b00bd2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}