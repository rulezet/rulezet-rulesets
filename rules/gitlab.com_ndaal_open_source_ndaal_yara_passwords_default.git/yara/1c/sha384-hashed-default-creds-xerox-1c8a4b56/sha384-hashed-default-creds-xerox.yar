rule sha384_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f59f3f003168cf3be04c773948548df167d122d9b467e255afbae5168f20788ffb7910c8d2800bdd976f0f50cbf523b4"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7ffd57cbcd46bc1359d376fd84a4301e2937322afdfd716933db49a5aae2aa59511dc8d3143e2cf55d00ef0135b1a7cb"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="340cf197b38cefb4d11c6cb751420d74c8b024c3cdd01d40834d5e6111abfebfbf7ceb932ce625a7d5598fe3ab4c366f"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="f59f3f003168cf3be04c773948548df167d122d9b467e255afbae5168f20788ffb7910c8d2800bdd976f0f50cbf523b4"
    $a9="378f4991427116129ad28742b83054e3041950d08287036c8651d997ce79a143c361e3ace84e622ad22625f6145cf114"
    $a10="7318735a5559d423f7706bbb8b6f10a610cb1b74b308a0e17849ace4bb3a34db34b3b126aa3a8d73b117f98be0e4af67"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="d333628ea675f551d8a68df16749c52c746948c8a1ab61b0031400d24968290bed7787df5eabcfc07d630a4a967a9480"
    $a13="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a14="dd6be5a723c7fc7089ca2d379497b850f5f77c1800a590723e79399615f0f2898b745067325bfc45fa802d3ad6653edb"
    $a15="87726115cd03a1716d3bee518edbdee41a7a2d7fa490cef94a0a930ca2453a9befec57895fc5adf594562f5f1a293e4e"
    $a16="f18fdbedc2b8086d72723695340cabe698ca1897494f4bce94d1b53b2de2a802f90e09c0a7ceb762f4472c7f5a7348d6"
    $a17="592877d731e1a78fdc1be0fe20e47b95b1da70f8423186a693368b221d2f408fd3987e82ebc3ba77aa51dd512084ccbd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}