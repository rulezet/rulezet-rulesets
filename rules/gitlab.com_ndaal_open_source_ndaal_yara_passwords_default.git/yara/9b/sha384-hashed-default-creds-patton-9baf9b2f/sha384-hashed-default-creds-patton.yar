rule sha384_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a1="9d0514b37dee26bb60aee45ba5a54174520be70b772d1b46a4f87cdfec073ced5312dd6085c3f346ee8109f2872ea427"
    $a2="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
    $a3="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}