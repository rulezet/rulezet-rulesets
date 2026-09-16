rule sha384_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b31bf3fa900da5ae5423ffcfb8523a3a3bf353550336b9d2a3f790795bafa7db09a950cc1ce43b58b6186a4e71f161f"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="962e1b5102806c8a8169f55e210ad3b517e73367f296fa1391a4dda4f2e9fe4d1a2d80e5764b47f031a6b65bc38b6b59"
    $a3="200ce4a0cd99ffbb8dbc1d2414b7c0c216c4d042e7a86d035a8da2fef8eeadd05da0285ac8bbcba2bfc600567f43a7a6"
    $a4="83b33d3fa09c9d68c064d9d8250a8d022cff899a3e5ce77f07c4c6f361e37be2b8bbdb6ded6b20037af9af4398d00fa9"
    $a5="9c0d10f1bbbc84a59f1611cdba9e33db66f00e157f4d254cd295bc3f71a0a849431a7499e23aa6a18a7e605a68363a14"
    $a6="60d668d39888448e9556498bddbc8978969099933afb927e05283f029b91bac415beaf7d70f59fa9ed27af320815c6ef"
    $a7="a3124031782d96ed3c9409bd1872de96be2981a97fc8852b8da482780150cb7b59ce00a12de5fd0b5adcc3fb51839788"
    $a8="4c31fa9f2233521784230faef6e76e1ad97eebd300ef2675ab55ef8dda8b0564ad3a562939020d4ed678ac5201d75845"
    $a9="0e69d9669ab0fe4989553c463d738a416237eed0e502bbd4411a7d55f1284b21d407e087e837042ac27cae5e3651840f"
    $a10="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
    $a11="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
    $a12="235defe79fd4391c111c606037e4681de40173d7a41db51c74b4f6d91902dd5dab02f4413b5b780ff8001bac989d310c"
    $a13="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}