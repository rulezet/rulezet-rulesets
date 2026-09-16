rule sha3_512_hashed_default_creds_psionteklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psionteklogix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="ceb8d618f84e799be762a1732cbfe4bdd2d338ae28bda438059cdc4e93811dd2b9ef37769b455862b5ce075fdf979fa65ef65ac3aab2f9f2863b84efb9f4fffc"
    $a3="1fd0b56da32394c212a5aa993675d12eea0e0761d0662fa6ec068bd96830cd47cc914c0d8d12945f9fa346303aa91bbaf92d02874b27fd0369b36e6544e21c4c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}