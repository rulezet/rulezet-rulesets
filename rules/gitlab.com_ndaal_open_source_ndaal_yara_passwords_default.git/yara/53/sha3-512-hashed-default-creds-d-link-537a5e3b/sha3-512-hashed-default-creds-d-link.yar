rule sha3_512_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="3563dc2d6b64c2f5da08e9b3884b1e4a56670b55f7e269d039a956e581b23c8233ea525547bd499ef708ce509bc6fa7ce752bfc7e59b8d32af620251c5a955e4"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="922fef93df6adce63e5debf49504b4a81ef5a4a6425c898fc1af352d6d0b2ef56e44b9ac8bc7cd7843168d080a374126450b5258b530c6841a11815dfeca1a06"
    $a9="89cfc1376cba122c6165d66d04a5c22c51fa9172a5e111269622cd4d406b11497456a6ee97c4083a0d8a0fcae54bc5286241cf828c880fb01c1954db50491ef0"
    $a10="f67522486300911fd85bbc40abf440ec940657368f80407a893bb34d1bf44f3b5faab5fee1cf14bcd54d8af0fb8b299127df856a4d6bd5cdba3cb8cce470342e"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="466d655ff7b75b83884a7298ff86efd6a6bf91bb6e42b16ff13f02179d3306920e72602e200baff0203b1bc4cada5dd815e454ffffec44c321520ea4c14606ac"
    $a13="466d655ff7b75b83884a7298ff86efd6a6bf91bb6e42b16ff13f02179d3306920e72602e200baff0203b1bc4cada5dd815e454ffffec44c321520ea4c14606ac"
    $a14="28ab56f8fc14b6cd5b75b806d4eb823ac34307fd2a0375a12acb9fb0f31387f625c8a77d436ee396a4ae2071265149a0bae4c1a0cf8a3eae56e45f09a4a4bab6"
    $a15="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a16="8e8aec4a9221034f087648cc318d1d82aac40e222f81c52ab3a2a9e47825c1144bfa2139ba493ee2e9121083cf2ffa3d4649d9b20a6bf840082f3e8e285e1522"
    $a17="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a18="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a19="b94ab49eedc3dd6e0ee061afee22c21f293bdf06c27fa40379af778add1c7019437afa2fbc5b5dfa6a821e541eea81363e4032af02150f46276e8045b7218817"
    $a20="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a21="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}