rule sha3_512_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="966b4fe3e73f333c646c27fbb7ce1775e5d6ab7ef3049b8b744633947fb1bfc5f7b97b977bbe53e2a1c03b6e75e5e52a954b73e0f97fbf1af3400e2da40ad5f5"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="09558640f7654d5c32ec7d54251104041d8f10aba9b8335909da23f1b8a989d4d161f8314814896a9804b73e8eadac6a71effa023aa3d85b1603f2213c4c512e"
    $a3="3c177ed17b801e3a825e264e0877b1556e0ad8c603245172937ed840dfdcc5a96c7b80e2f6c72e5371b9c5a54e45dc7160bfb76c485a93908d1da691a2f38f79"
    $a4="12dacac848b55fa0faad79d5a0e559dcb3682b0d96052bd1f1bfcd31da7a01717e0872c50aab7d2533fe38179b6d646aec4367891404beb30935140f39670ef0"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a6="d959d6edbc5408727afe0149deca7e072af72d17cb681d900a863b5bb89fc7b8e86a3ee800c28d39581867474a317998daec33cb8f2f18f2ee2afe2b2dbe1e3b"
    $a7="485a32f0e4d8ff6eb8f08c48cd1cd5715322de7f932e8b0be84a0e14673e6aaaf5f9f84ecd53c3fd60f63d2d6215d5cd12f4699c39b3523761b445cb1c37a1a4"
    $a8="751294b54e6941a95f3fc141df06dcf97f6d923c8e0b9ea365b0e1a268c0d6595640a087782fd37b49d73fc8a376229a0f3f2c0f07291051ab3420b9b4d909d9"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a10="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="730173b90025a45193d85ab72578489fef51e7d8e7861145b2a4c22441e3d516174d8d7df80ec6391659679ce1fe55475ed6ce8829dd17c88a301c3811bd7a18"
    $a13="c18eef2d8c54f39b6e61cc2e7ec2c083a2049418560b2c569b5c8024cca829c07e3b6b26d091c5e4c71c37adf48fbb437f2fb04b373aa20a73a8ad1359519f5e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}