rule sha384_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="5ad35c172348a4dee599679196b2ec308f5ccbd575eddb4d21c37c6932802e4f25841882e7a278b9d44f2f95ae71164a"
    $a3="338ef44a9ff34626247ec1e36ea906ec09dad827cc3e931bcc090a76767a9f7c3131e7900eaf4ba34d3fa58f3e0559df"
    $a4="15a46dceda9fefd948db2e6eca47bed3d7ae64fe465fa26b30630296ebb6afd127b80f9ece97ff81ae3e7873c046db9a"
    $a5="0219ed5747e8868d635618d1f31e78d06c52846eacc07b0b29965073c0dcb4547cd25024c28d482591101624bc4d2842"
    $a6="baaee88f2c768f96015300016466582b550154738d10383eb086485a9bda2633937ade2dda507b7157e10cecbc925b89"
    $a7="0219ed5747e8868d635618d1f31e78d06c52846eacc07b0b29965073c0dcb4547cd25024c28d482591101624bc4d2842"
    $a8="57438364fc03adb40e633549e091fb4301ee9806bea075cef8f2ed1676147c42df5cfabd2352d2e1c62188c1ee19cde9"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="f5889a6a118d1f3968a0216060e6d861eb3b2fa05fc5423674908d92a0c80c335750f12790fa95e03976ab94cdecca47"
    $a11="73114c7a760f92362ccafc80b500ae704167906e9509d6997906df729b4f86e678dc8a9ae7a7f926874920b67b2621e6"
    $a12="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a13="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a14="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a15="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a16="fd6c09e15817e414401f46d1d6e4199aac71a2000a0cb139d9076b2ec294a8436d9f4177835f1822aa02c476be2aa64c"
    $a17="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}