rule sha224_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="422eea0f677a9db3139f4b3ee62e5bcbd1b7b9790ebe5df7c787141b"
    $a3="ddb584a8a86bf5f4b700262bf5901f473d133869fac0ad86215ed2ec"
    $a4="b112ede8c42151cf6c818f0e3c916ecb1571efa14706eadd68ebba86"
    $a5="a6f50e761c4b9123d69e182b24c3f1741f1c9a7e522f5869ad331a2d"
    $a6="850c27f367d8f2531f59ea6c9bec6cb46f7ad5c3525121a87875e6ad"
    $a7="a6f50e761c4b9123d69e182b24c3f1741f1c9a7e522f5869ad331a2d"
    $a8="b0b8d261493551a5547df0683d64ebed2a054e5ff1c9bc2687bb4057"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="e0537f07091ae104db4a8b939b3c47b1b8c2f4f38c55ee45f871b22b"
    $a11="d9013712ed33598db5fd4ce9b8ed8709bc807fa71b361e9c7e2089a6"
    $a12="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a13="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a14="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a15="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a16="aa0aa1755df23ef15fb3315053fe450b489417933276cf16b71170e6"
    $a17="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}