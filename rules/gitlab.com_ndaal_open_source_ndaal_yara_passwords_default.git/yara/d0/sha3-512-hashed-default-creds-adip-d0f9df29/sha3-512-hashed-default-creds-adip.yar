rule sha3_512_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
    $a2="49a3bd9a59750d43cd342842da8420e3a35a564a013e9719f046b3c2ccc8800b1ccbb8fbb766f9888acb971bfdcb23ba1016eb10a092f8eb0945bf50b2857f7f"
    $a3="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
    $a4="7a60196f7917d91d476d007c8f04a5d9369add010ac2c6831e2c0fcad4e2ff5b6e9a6ff0d6aed0e9445f6bba1dde8f97face7569dbc5bf7ffbe480d1e070611c"
    $a5="a37046b1875c3749a963156605aa4e2de7daaa11c8e4d05dbece0e9ac77b00aa7e7872cb9a9d134569d71d706f911650f2692b8ab4790550ef769f93b3810312"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}