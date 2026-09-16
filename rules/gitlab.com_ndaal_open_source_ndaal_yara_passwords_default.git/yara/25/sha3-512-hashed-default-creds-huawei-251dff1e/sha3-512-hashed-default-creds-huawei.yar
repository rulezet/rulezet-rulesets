rule sha3_512_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="8b6d1aa2a62446c7b9e24b6caee8e1df84282b79a4ea2330fe6778e4a534dfb26a23aa77aa558f880728428e7e451c54acb6e1667e070ff59cee5f5807f3eb10"
    $a2="01453a3d181c85cf81f5c5b79303234fbd8541902e3225cd4b010d3fcc979f71ec3aec7f234841e67ccdfc8b2538be563243baca5091509049d5398c76ca9872"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="29b9423956a3316c847c2cebaf27feb60b2ec7c3f2e967343775d4852abfd2141795b5d529a97addddda541dbd4f1aab45ec3eee1c3cfa2f48ab07cd90418f12"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="512c45c5271405fa75225a2b8d2b2b2fd20863d9a0d9f4e42c0c53f0952fa1b7edfd05fe7683fbbbe5a734ef3cf693484f3874238194de58ed31e3962c0c04f6"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="7891e4bb64d7b0c9cea1a051300fdb921acae2bf2f1bf18b4f8fd3f94c0fdb5fae3728cf6e49f0fcc9ff9abc24641835780f63b7eae7a7c2eb7aa71533f295f5"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}