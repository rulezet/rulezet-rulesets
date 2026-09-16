rule sha224_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b16fb3b924e301032472a00a31b2f40c96b19018bac9dc2713a870e8"
    $a1="3a4b8c32bfc385a9694f8b7a83470e5afb0decf1054fd63714137af8"
    $a2="212f6c99f11e5c23139eff0202c1efe2f7711b49316c506df3bfd8d3"
    $a3="212f6c99f11e5c23139eff0202c1efe2f7711b49316c506df3bfd8d3"
    $a4="788018a63e19a251fab419cf26aef5332dbadbce9ae9c09e7cf4d3cb"
    $a5="788018a63e19a251fab419cf26aef5332dbadbce9ae9c09e7cf4d3cb"
    $a6="7b0cff901324c4aebf445b36f35f093c46c597dd81b85079a18ea53e"
    $a7="7b0cff901324c4aebf445b36f35f093c46c597dd81b85079a18ea53e"
    $a8="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a9="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a10="5b04bd2d190d52f06df012761def78b2c0cb9f99270cd078db2663ef"
    $a11="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a12="18792bac7bfcd5a3d4d5d6a3a66f9538b2fc18ac0d588ec8567f311f"
    $a13="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
    $a14="9e21dc3c98e10cb9d8c3a94295e8fc946c1d96e7d1db93ad65e46d20"
    $a15="b9017ad210e8dfc00b6ca6abcab1ee39a262b54165b8ac84b221598c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}