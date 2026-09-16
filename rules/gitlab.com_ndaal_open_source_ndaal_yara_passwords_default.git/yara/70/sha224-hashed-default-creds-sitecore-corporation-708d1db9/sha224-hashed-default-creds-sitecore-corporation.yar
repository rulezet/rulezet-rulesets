rule sha224_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c681e18b81edaf2b66dd22376734dba5992e362bc3f91ab225854c17"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
    $a3="b060e3dbe9c4eeae27b5295ae937703c3c8b8356467df13b0526f7f2"
    $a4="c681e18b81edaf2b66dd22376734dba5992e362bc3f91ab225854c17"
    $a5="e4538f747534ffc7ba7fa8c42319e2aa17dd02d27f7f1150a2266aeb"
    $a6="06c9f71496e24dec6acc44895648cf9ec40b5cebb7bc4858a3c69f25"
    $a7="8668490342591ecc520b05c40b690ce79dc3f9f79689ce1d03df2306"
    $a8="2e0cc996fafd71bfabc0717628bd3296306b078910b68f081f3d3fcc"
    $a9="8a9b11626feac5a3b533fd4d2b07668122b52ec10879efd32a5138b8"
    $a10="4fde0463771d8c4fb82794d5d6d003725c819dd34360e7bf9c70cffe"
    $a11="11e5224a236ade3682067eaf06127ba7f92f3cae4335058050d29808"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}