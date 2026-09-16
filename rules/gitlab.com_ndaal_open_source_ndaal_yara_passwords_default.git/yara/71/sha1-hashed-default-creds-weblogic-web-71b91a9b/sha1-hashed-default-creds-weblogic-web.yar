rule sha1_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9659699670b30983eb4e3c22454887e3c9c6ce39"
    $a1="9659699670b30983eb4e3c22454887e3c9c6ce39"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="9796809f7dae482d3123c16585f2b60f97407796"
    $a4="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a5="fe96dd39756ac41b74283a9292652d366d73931f"
    $a6="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a7="fe96dd39756ac41b74283a9292652d366d73931f"
    $a8="d1785ca28c3a4d29a6edef1520c544b838a93db3"
    $a9="d1785ca28c3a4d29a6edef1520c544b838a93db3"
    $a10="1a8565a9dc72048ba03b4156be3e569f22771f23"
    $a11="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a12="ebfc7910077770c8340f63cd2dca2ac1f120444f"
    $a13="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a14="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a15="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a16="31b01d405f74a13c94d97a9e0287a511451f4dc0"
    $a17="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a18="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a19="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a20="44a985b851c5ae75033309afb7522f84b8238d1b"
    $a21="44a985b851c5ae75033309afb7522f84b8238d1b"
    $a22="af8f60dd67906ac8287ba38343ee5f6b821ce6d9"
    $a23="eb9b3354dc45b63d845627148b778f4c3d548311"
    $a24="31b01d405f74a13c94d97a9e0287a511451f4dc0"
    $a25="eb9b3354dc45b63d845627148b778f4c3d548311"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}