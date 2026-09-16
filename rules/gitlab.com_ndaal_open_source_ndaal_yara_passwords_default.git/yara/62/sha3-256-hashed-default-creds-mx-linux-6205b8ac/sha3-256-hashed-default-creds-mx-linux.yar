rule sha3_256_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a1="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="81e29bbbd09466b1ad43b87c8797f2bb61e5a4b3760c1842a4839fa295604aea"
    $a5="f7e49fe2d8f701cac98e7929e888ceda47160dfc155414c9c0012255192d1b68"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}