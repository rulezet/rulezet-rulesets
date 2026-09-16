rule sha3_512_hashed_default_creds_qlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for qlogic."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="079c79a43eb850cac936221754973327b823e22513d3216a0320b252847eb0badc3f0554bdbe915962d3681e883ae9ad0e88e57f55d1d8bf13da9f93846aab09"
    $a3="079c79a43eb850cac936221754973327b823e22513d3216a0320b252847eb0badc3f0554bdbe915962d3681e883ae9ad0e88e57f55d1d8bf13da9f93846aab09"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}