rule sha3_256_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="8e90033587dd20136a0a01f5fd60c9c5b3dbd4c7a861fe3a5103770f5bff00ce"
    $a3="85f8cb58213e29c45002fd406a44330b8f7f2bdcf83f8f75e415aec20d6e67c4"
    $a4="360c6fa6f091e13c7ebe465e778892f5619baa6a2207e70193d49d23b56fd6e4"
    $a5="de56b22441814353123f3f44762a6627fc4ffd8098f99e9832430a1f32d75304"
    $a6="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a7="8bf690914ecd52802990ce2299d4a6f370d9b412cfae6fa9a13de5710ec200fb"
    $a8="9c86bd4a1aa16e8389fbb5d8e26a4ee7996cb3e983206dafaa408cd1d3f445e7"
    $a9="d29734b14647584c84b83be00c0cbaadf37d4047296f3669cc10604b7bb0b705"
    $a10="7cb024b68f5fd8f14db8f0312c8c3c9f493e53965506736e4ee3d397da06d56c"
    $a11="9fc4a62b0da15acffa43ecc9785b713e44232ecf2e8e9bb30b7a638d90ba2ab6"
    $a12="ec892d8c22086b42f17af010d9a8db93464697f29b27df30a73679f9d867ed4e"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="f4d6ed1b56b50792c161e7b440f2931279901d1fc97791c69af7d3d2381980f2"
    $a15="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a16="974984b884d014413e0f38d1266b13dd45821d796c0fb2a39d7603b76eb3ac74"
    $a17="c4c2fb2f0a693d7fdaa22d59a988855d57ab900db35c8f82abcf0dbad564bf04"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}