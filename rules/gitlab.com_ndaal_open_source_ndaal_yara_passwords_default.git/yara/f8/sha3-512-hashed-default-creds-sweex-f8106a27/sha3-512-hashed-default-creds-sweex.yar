rule sha3_512_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e1d999fe06b3fb7277ea27201394bbd012aa62e940931a5ec71153f9c9f523b7c5a022a7d9898a7cd10d3d4f5b40efd20e22b24869c568a82d3dbceeb24dea4"
    $a1="6b69dbfff44c9016c82bc4115674954d12f4077cdc7f7a25231a13e0f46f6cae17e0e4424b09d629935b065667b62c9c7e3b73d98be6ca70863fb7916f5d2f47"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="d2082958b8a3adb6763e540bc84cf911872791ca5a08c0fbbfd0b5888516e5ea4bd7298172cea3c269d06fbce8134607a61140cbdb1ee9fa3611a8e5e607393e"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
    $a7="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}