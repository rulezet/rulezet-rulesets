rule sha3_512_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="9adad458eccd78e5bb821ef35c88a588e0d26e3d53b4847228eca37dbbf3d888257204520a5d0499e16486885dbcd4d81529345c6f8b5dbc9b5d8301bdf6809f"
    $a3="9adad458eccd78e5bb821ef35c88a588e0d26e3d53b4847228eca37dbbf3d888257204520a5d0499e16486885dbcd4d81529345c6f8b5dbc9b5d8301bdf6809f"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="2c1c0aba283f3516f0065fba98b491e2a0f4361d06cedbe4ade4a92766584b7fa82865b0156fc4a7b7b22062535d32fe9e1c76fcb3bd225d40ba613d8b119c72"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}