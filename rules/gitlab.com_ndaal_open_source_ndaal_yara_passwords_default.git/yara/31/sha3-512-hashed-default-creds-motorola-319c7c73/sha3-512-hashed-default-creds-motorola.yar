rule sha3_512_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3fd49aaf123262c9488283fe59596fd271b6e9da0978e5d9cee0168c078996d9705fb03528f2a49a2136b81bb9008092265fe7fc2d082279296f83f37bec538f"
    $a1="b494d71e9282ce0e4abd722aea47bb98179de1bb997655da07a9e3d4e29eaa169dec383ebe573b59c36741f70a517d513dbec037fe13b451c01d88a9eb3023a5"
    $a2="afa4f4598504512a701d121a0102edbaef2723e764399535d30b7f1976d204de734a67d495cb36c4707c042b4b7b90ab8dd0c8ee2120f42a21df06777fa9992a"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="aa0f96477a753c367edb9be48f0f5561d5ba9136c6cdcd9b59415966301d6c88b3df8eb446fafe1979321d7b81677c22bec39485bb2056a0e76de73d5f32286a"
    $a7="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a8="0c757889a9243541ad16cae83b4d1aaa03b4206691d9999de0846c21839677b5c56bf79ffe3ebff27b2fd914b95167053c1f2fed76468a79af1e1fc78021b579"
    $a9="09aeb34e3c243c9d5365b896bd62588df6bde484db7c7dae0c6f3a828bff09c1a1b853eaf2c422349101a7301efeb2e23a80c8bc91f747f661c7af54697ea125"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}