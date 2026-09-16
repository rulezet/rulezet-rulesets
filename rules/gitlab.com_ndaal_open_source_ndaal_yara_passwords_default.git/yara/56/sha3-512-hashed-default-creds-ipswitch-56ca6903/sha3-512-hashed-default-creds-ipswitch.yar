rule sha3_512_hashed_default_creds_ipswitch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ipswitch."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="9627f9c798d24f99c335b2040cfd21b93efb80bb9204dfcea39e6f871aa455e21a8860092280540a9d4fd201cc3c7ceb36ff5a31a56279e36a91e0e720f4b0e5"
    $a3="3b87fd8b5baf29067056c3df77701ac8ec80ce81538e943a707dd2fda0e919aa118a6a112fdc7ea4953bcc01101c07a46ee35de68462376b267cd305cdebf3b4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}