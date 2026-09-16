rule ldap_sha1_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}lllplnCzCYPrTjwiRUiH48nGzjk="
    $a1="{SHA}lllplnCzCYPrTjwiRUiH48nGzjk="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}l5aAn32uSC0xI8FlhfK2D5dAd5Y="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a6="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a7="{SHA}/pbdOXVqxBt0KDqSkmUtNm1zkx8="
    $a8="{SHA}0Xhcoow6TSmm7e8VIMVEuDipPbM="
    $a9="{SHA}0Xhcoow6TSmm7e8VIMVEuDipPbM="
    $a10="{SHA}GoVlqdxyBIugO0FWvj5WnyJ3HyM="
    $a11="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a12="{SHA}6/x5EAd3cMg0D2PNLcoqwfEgRE8="
    $a13="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a14="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a15="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a16="{SHA}MbAdQF90oTyU2XqeAoelEUUfTcA="
    $a17="{SHA}MX8edh8vqo2ngaR2K53MLFytIJo="
    $a18="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a19="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a20="{SHA}RKmFuFHFrnUDMwmvt1IvhLgjjRs="
    $a21="{SHA}RKmFuFHFrnUDMwmvt1IvhLgjjRs="
    $a22="{SHA}r49g3WeQasgoe6ODQ+5fa4Ic5tk="
    $a23="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
    $a24="{SHA}MbAdQF90oTyU2XqeAoelEUUfTcA="
    $a25="{SHA}65szVNxFtj2EVicUi3ePTD1UgxE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}