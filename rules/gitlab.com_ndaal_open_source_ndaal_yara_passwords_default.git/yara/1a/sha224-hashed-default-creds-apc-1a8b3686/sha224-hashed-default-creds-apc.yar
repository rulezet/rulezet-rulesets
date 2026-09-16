rule sha224_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a1="77044a646ec05b83a2d3f9163bb765abbb115a34b2df9e198adf84ba"
    $a2="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a3="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a4="58714c17b0ab4e300bac7f3dae1b844e421b0832a84e0efc4cc0f9bd"
    $a5="92ed51bbe9c7cdf1c50d112af91a0462a4888fedf81965c66c55fe59"
    $a6="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a7="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a8="897a693535e115a92c26661dc89479d4d368723e7e158ac62d89e161"
    $a9="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a10="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
    $a11="8db99454bd01e283c9a1829c1a7fe73e594669a8c772a56ac91bf96c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}