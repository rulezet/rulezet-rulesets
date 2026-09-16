rule sha224_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="08061385a690e9186388783490e0b60243ae285044a8b18d514925ec"
    $a7="08d6ddd6e0e67b07294de2d523aa3dd5fbef4e9c817870a0f5c10644"
    $a8="3febb630e97a4b8be0b40acbeb4edbd88a1483c57187f0493d7465ec"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="fe57ad6821f3f73db2ee165dad3eb2523dfae418de8e92534f0bce7b"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a13="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}