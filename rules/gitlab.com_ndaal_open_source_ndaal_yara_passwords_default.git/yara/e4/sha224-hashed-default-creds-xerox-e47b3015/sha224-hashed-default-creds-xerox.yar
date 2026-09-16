rule sha224_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f0aa5eeec6b9c07a2698c62ffa65358a0864533cf67669224173277"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2cfcbdc839cf550004a0115a366cd5260becb7269f038e2a1911f44d"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="cce54f1ae2a54b7c3ac10d67ce99e2784b17c62a97273b7ac5258922"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="5f0aa5eeec6b9c07a2698c62ffa65358a0864533cf67669224173277"
    $a9="dca08c944a652fbf0131bf7b15ecd38fde5539d5a6226171379a1816"
    $a10="9cb7b5b974b6df070cb60bbeb134ea461541b92187d54372f4b144de"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="cb46f8b949bb5f7c4e9344bff20c643379499671bc47493a91d3bb49"
    $a13="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a14="8a645bd4d213e232e9f9eca4dee9f004d1da2ec0eb02e6b8430f7ab6"
    $a15="b6efc39b10df3df477304e184eee31c26b5cc32c6c82130cc5592d81"
    $a16="efe80e8af9dcf6f64b9ef717251f53057a523a80c757b19c9f3edf18"
    $a17="972d86c7854a40824773b4bd4b148d518672b4130370b1e2d41f8b7a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}