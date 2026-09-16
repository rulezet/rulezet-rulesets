rule sha256_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a1="29a0ae2eec6a90eb8100d0bcbf063c7081e60277dfba2a9db821074776bc44bb"
    $a2="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a3="c06f6073897e5e857e12be420e89d62163e5b0e73317d0a6c34dd34dec57c1d7"
    $a4="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a5="948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"
    $a6="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a7="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a8="12d27e106af46b4b9ca8772d97f1855329a420d873ca738b7b11c68d285ca71d"
    $a9="2b8fbda969a8aaa908e763c57e6b22a1697b7c0c5f95fc35b95d492fcc54d082"
    $a10="2ab6d53e717a0e0d773ccfdb8b0e84ac494729c6b567c72d256b883a9db17ea8"
    $a11="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a12="746ff992cd97391b15891f93dd1ce02908c33947c60f1a95fc134d40874e5ac0"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a15="73170a99e6da9a0d8b381209436bacd8cfef30ade921a2ca1276880611000138"
    $a16="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
    $a17="d7c1f771f6f06139d6f4ada46a6c6f50b0e3fcfb6b4b2bce3721aa07c11a4096"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}