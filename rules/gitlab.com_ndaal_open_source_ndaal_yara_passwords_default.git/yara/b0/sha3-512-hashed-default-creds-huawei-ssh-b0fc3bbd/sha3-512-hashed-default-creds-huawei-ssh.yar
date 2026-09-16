rule sha3_512_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a4="88fb5aac8c14c70d3ec6c5f8f942f1abd2ac3450288f9ce235c5b3a1caa8059fa9731d9e8e17db2fed38cc23eec24c2fddbb307234e951b9a906a76c0473b783"
    $a5="88fb5aac8c14c70d3ec6c5f8f942f1abd2ac3450288f9ce235c5b3a1caa8059fa9731d9e8e17db2fed38cc23eec24c2fddbb307234e951b9a906a76c0473b783"
    $a6="0e34e699dd1503414c8ad8f2779d761c2d6839d21b307301a2c7d7f5c025d39dd49878d778d3f0c55b212364941082a10616918779282f28915a3a1731850f34"
    $a7="4bf56c5f5668d38a0a556e447ef89b015908367bde6b2961ea1bdb013bde8158a50842cad00152be5c926aaa8c8cc8e83dbd05c44085e797318a4b5a6a5be55f"
    $a8="a1722b1c88ea54cc3e561a9b1565b6e57163446bdccbdaaf974280648909d3c046d4d489afb4aef1266449c50db19e8e47b6ecf2365f45e04b19606572adc89f"
    $a9="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a10="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a11="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a12="fd1e71eeca9068e85b237cf5d2a5068762c77c66e69ddaf3662b9292898a5ee8767cf0ce9d7f7b7c5cda5942c8e1611b04a2f2ea074d97a2c19c342a6527d27f"
    $a13="fd1e71eeca9068e85b237cf5d2a5068762c77c66e69ddaf3662b9292898a5ee8767cf0ce9d7f7b7c5cda5942c8e1611b04a2f2ea074d97a2c19c342a6527d27f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}