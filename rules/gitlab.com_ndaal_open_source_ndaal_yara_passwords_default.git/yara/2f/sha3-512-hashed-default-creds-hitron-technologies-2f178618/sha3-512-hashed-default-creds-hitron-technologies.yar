rule sha3_512_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="688c47c19efe46994a5ea25bb551d06ddc1526e3e1b5891820900e3dc4b79101c154addf51dece55c69d7a3483db6da29f6cf67e27a46f5a4235057f69fe9685"
    $a3="d5354c001e9588d0d71c080f26ee819ac6265e97682d2c7e8dca0b2cf949c3b82b8f3b5ef04d8f0d625a756bf27b1c69eed6256460c0ffdfd49dc5a96c14218b"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="c61d227b39bea341bc41a91886dbd030797f99b8b1b70e00251732f723b446cc6fa5892b8ebd0aa8cb40d322ceb810fc03f770a60b90430f00547b07a7df92f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}