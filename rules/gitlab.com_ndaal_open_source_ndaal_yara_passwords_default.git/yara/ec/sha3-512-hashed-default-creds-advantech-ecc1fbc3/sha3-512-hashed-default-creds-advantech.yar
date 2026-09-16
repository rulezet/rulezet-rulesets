rule sha3_512_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="921c30adb4f6a782eb7e9d5497aac8b85e9d17d000c6c7cbd34ecc48b1f5f4b634a0fbd7e4f1b944a79c5a4ba9b12950c2c444d7b20b47e230d1e8f3b7c7484d"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a7="db8c45335d1cae5f0d6550bf03d1065476852b1db6964b559f2d747de81e912d324576491e7f8f13e95caba7587111d9d5548cbd9eff7348eed3eabc538ba969"
    $a8="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a9="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a10="17ea18adaf471a26e57a5091f0a51eba3d04a6b7d52331171bf33f2ea6ecd5437edf71c62e15b5f1cdbc3252c12ed57e296011f2af8b58631dbacbe166ff0b74"
    $a11="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}