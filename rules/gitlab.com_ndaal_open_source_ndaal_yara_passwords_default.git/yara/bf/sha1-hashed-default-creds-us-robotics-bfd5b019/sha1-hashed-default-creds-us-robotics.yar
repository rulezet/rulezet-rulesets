rule sha1_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="5bdcd3c0d4d24ae3e71b3b452a024c6324c7e4bb"
    $a5="5bdcd3c0d4d24ae3e71b3b452a024c6324c7e4bb"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="8cb2237d0679ca88db6464eac60da96345513964"
    $a9="322444d3bb52c341f429ca0454f292dc242f315b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}