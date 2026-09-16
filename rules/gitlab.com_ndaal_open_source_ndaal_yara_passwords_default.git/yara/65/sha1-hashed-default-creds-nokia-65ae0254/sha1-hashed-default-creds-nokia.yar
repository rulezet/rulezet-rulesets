rule sha1_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a1="db70a20f403dad43acbcdc0290862079d7300f7e"
    $a2="bbf0e00dce424049433f5aec1d93013db3698303"
    $a3="bbf0e00dce424049433f5aec1d93013db3698303"
    $a4="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a5="d2a04d71301a8915217dd5faf81d12cffd6cd958"
    $a6="8cb2237d0679ca88db6464eac60da96345513964"
    $a7="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a8="01eb84f052ba857d610a26815628d5339386c8e9"
    $a9="e3272363f7e59ddee3c6be2811f61d4e8fb3f002"
    $a10="d61db83635e5f720433ef78a30f3cb269df0c0da"
    $a11="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a12="c1f46c805200d800a0c0185b33334b263d34c7ed"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="8cb2237d0679ca88db6464eac60da96345513964"
    $a15="fd3cfc02834858b6847a18bcd6e8e8c145fad487"
    $a16="f9ba98a0694ade0740017ef26f79efb102609c7c"
    $a17="f9ba98a0694ade0740017ef26f79efb102609c7c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}