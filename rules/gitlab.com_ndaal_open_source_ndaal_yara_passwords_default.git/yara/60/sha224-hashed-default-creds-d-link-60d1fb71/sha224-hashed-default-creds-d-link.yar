rule sha224_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="be0b39b08181103d1fa47aee92a84873de78757def95bff0e9d74dfb"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="6b1d3d49f3829502026e0000a672f19bf9d284558906d13417012a7b"
    $a9="35807539335d3c054790313c4895fb2c205f5bdb638833c27b2b534c"
    $a10="888fad770c3a27c39b480fff6350198462b46ff1d4bd01a6ee7dc24e"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="5c54250368d793966f71d96967d539d35eec60cf9046b70614d8f19a"
    $a13="5c54250368d793966f71d96967d539d35eec60cf9046b70614d8f19a"
    $a14="70f7383f38ede73626f931c05e2d7ec451c032e4c453921b05c1a537"
    $a15="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a16="a33b3cce9f96643053691faec28d7aabb5c97ac29ddd95a12ba639b5"
    $a17="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a18="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a19="91dbb637483891700ae70881d07c35cbd5f59177b0118fd4bfa647bd"
    $a20="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a21="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}