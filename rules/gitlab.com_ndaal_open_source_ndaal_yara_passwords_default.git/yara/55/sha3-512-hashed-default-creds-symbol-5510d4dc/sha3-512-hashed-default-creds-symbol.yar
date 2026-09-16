rule sha3_512_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74ae2367eb66737d132c500d96a18da3d06d2887db244161ca35c95fd3d4c8f22597c96dc97d7c9b5c0f52a5a8c920655ab4dd768b68c306207df02953165cb1"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="5c518e23c25c76fd1fb1f36cf4cb56dd520db4cfb8e14216eba390c5b8ad727e3f580516610aa74ac67193b50a9349518f2fdf153dc0fafcc432960621fcf602"
    $a3="5c518e23c25c76fd1fb1f36cf4cb56dd520db4cfb8e14216eba390c5b8ad727e3f580516610aa74ac67193b50a9349518f2fdf153dc0fafcc432960621fcf602"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}