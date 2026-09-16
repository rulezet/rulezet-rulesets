rule sha3_512_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a3="468d495158f47cd4f838375dd4aa880dbeb244392e74f58a32d82d88d0574df1ece01af93b6e5458bc62796981d13a4d0097e4b45bbbd2b6236234e8168aa5c7"
    $a4="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}