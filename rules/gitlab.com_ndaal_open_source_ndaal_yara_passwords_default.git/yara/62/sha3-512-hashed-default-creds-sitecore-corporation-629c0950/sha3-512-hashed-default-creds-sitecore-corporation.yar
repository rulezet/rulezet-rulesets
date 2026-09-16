rule sha3_512_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8446c46ee03793ba6e5813ba0db4480008926dd1d19efe2c8eb92f9034da974d2171ae483f29ce3a79ed4fdd621ae1ed14fe12532af95ddd0728779ce5aa842d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"
    $a3="dd2b17333501a85e6ca9664e11796985a8ba3e1ce0361f2a1120299211b74e230b20129111b1c718d7a92bd0e65dac6c3c3f2effc07dbe2952c7422a681bb682"
    $a4="8446c46ee03793ba6e5813ba0db4480008926dd1d19efe2c8eb92f9034da974d2171ae483f29ce3a79ed4fdd621ae1ed14fe12532af95ddd0728779ce5aa842d"
    $a5="2dd6026b8a67945db1338abefffa88c1e8e20715333a19d40e28608edac39650c23a61f733ee4034c185ecec85872cba041030372f802bf3ddd86649c3c11b4e"
    $a6="4668897682ccd2b1ee0cae8dc55947291f819cc59ee126f5bd243b1852577414413aeed5780b5fb11090038715beed1b00714a15b31c8d9674fbdbdf7fd4191c"
    $a7="b4e84779167f0e5ac21b2992681629a9e4294ec09d907332f14faf50faf8a54fe92062affc98299671e1ab19cc496e24980c4023c4b7d4b528bb4bfb3cf23d7c"
    $a8="37e275b9f5a7067372be037c5d010e04d3d3ab0df5aab129a9379d9b9c27ecef3f7fa7bffab6582c18323df04c9d0c53cb63fdd5dde484f4227eb60f184756fd"
    $a9="7016dbf5432d40bf7ff3af555346672df8c923cd4bc01263950f19abd9a40b75342fb052af7871014239a1cd948874485ba0f15ae6bcd86db2f8ccc8ff896083"
    $a10="7c8e9b49719fda980d594727bd9d3ce693349bba9b303a492726ed7107551879be951f959c55e11b6b1fbd24668f5ee83339da547c04ebc13b56df8b12a03cc0"
    $a11="18d6dde43b20a09f2b16c82e99ed14fb22866de578e042737e69ae62f1272ebddfe910b3ebabedf1b68c53ed9fc778f7abe319cce6dd59076ab1c1a4bdc66222"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}