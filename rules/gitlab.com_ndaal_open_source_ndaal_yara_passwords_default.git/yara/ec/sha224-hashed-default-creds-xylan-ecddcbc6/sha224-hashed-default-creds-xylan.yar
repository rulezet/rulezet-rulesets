rule sha224_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="e22118ed1e9982ac90b2939302bd3c29cef5c5ff5dd462a8405f6e8c"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="e22118ed1e9982ac90b2939302bd3c29cef5c5ff5dd462a8405f6e8c"
    $a5="a8746091df3beae80988240b06d21e69466041008e55fd2acf77b770"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}