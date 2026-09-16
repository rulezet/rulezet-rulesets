rule sha224_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a1="7ba66c615caeb48d158ab4bfdebdb92f9417692e7e4f75a7d0eb17df"
    $a2="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a3="9b9f995bdc0d1115e2c520647a2870831fdbb20dde9eebff9cc5c942"
    $a4="c6e18245c22d972e525a5339ff9b162b9b2d1c7ff60885554ccbeb58"
    $a5="8d6f710723a22d47c4bf33367d9166cdde65a47835a6d60954763f1e"
    $a6="91f0572f12a77295e530583937e9d463c37c11760562e189cbb8188c"
    $a7="6263adf17b021d5f8043937837ee5acf8ad853a1ebe6d7aab9347af6"
    $a8="7a1aa63dd4f07ef81ed2dc00fd3660a61d353e937ad9261f18e86667"
    $a9="7a1aa63dd4f07ef81ed2dc00fd3660a61d353e937ad9261f18e86667"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}