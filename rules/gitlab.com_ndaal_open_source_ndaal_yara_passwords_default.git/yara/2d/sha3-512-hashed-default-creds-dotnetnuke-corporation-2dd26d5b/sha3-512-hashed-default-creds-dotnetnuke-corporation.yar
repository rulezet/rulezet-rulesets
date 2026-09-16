rule sha3_512_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4987d07bd730b884a4e4e023a369d7353c94750f5872c5af88bda4a1533b51300c6c39ad11ee3cca319313c1074d5acef66ccfd9d9ab885a40d0346af6d1c8d8"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="2642081248f96d73d4dd806c53e7a39b18227c46640ee506caf2ae6f741821e26a0fff9c9a5b8298b075e129592c12eb29d0e393aa385b261126de76dd2e70a8"
    $a3="ea54b4ab3e70c14e67688dc056c75014512d97162cfe3de27f694c5c342dc330d8dea865a615636c851064a93bded42ec5612758030cdf214b41016ba1496464"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}