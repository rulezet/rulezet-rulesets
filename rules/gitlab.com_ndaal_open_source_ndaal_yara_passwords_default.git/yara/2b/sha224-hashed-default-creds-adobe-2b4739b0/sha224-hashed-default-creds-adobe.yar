rule sha224_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="ba78a4b507e20f7d159503078770b0b1e3865e8ab6a9a85ab49a5486"
    $a3="ba78a4b507e20f7d159503078770b0b1e3865e8ab6a9a85ab49a5486"
    $a4="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a5="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a6="7e700da0235e83c73d9869ab93d07399ce10609bd057f718aeb1de45"
    $a7="c1af3864fa7bf5c60173de1f31a5c6d975a612ed809434946e5a0e1f"
    $a8="48b210d36dbf152408f768cf8bde8a706d012b76bcf88169891831ad"
    $a9="8d05e10cafca668b1c38ab4be6256a9803cdaaff40376b20b8a041e8"
    $a10="b5b56e63906bb925715eedca96f1470172785fbc7ac5814905c25c28"
    $a11="b5b56e63906bb925715eedca96f1470172785fbc7ac5814905c25c28"
    $a12="61dcf64c221209f4e886fe05706d8a1cdf7a25b6c17b4ca2d31b38f6"
    $a13="61dcf64c221209f4e886fe05706d8a1cdf7a25b6c17b4ca2d31b38f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}