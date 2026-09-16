rule sha384_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a1="e05524aab2c15fd593e47a7a2825ffb72cb6c00f2914746abd10d15a0e6c0b519e1b5142a7acf028f3dbdc470933cc0d"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a5="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
    $a6="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a7="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a8="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a9="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a10="d0f2bab80e7001a42d089c4c154253e8cb6032c8d41cf2b98c3877746d2257ad5f5263b6e220042654f673703330dcc7"
    $a11="d0f2bab80e7001a42d089c4c154253e8cb6032c8d41cf2b98c3877746d2257ad5f5263b6e220042654f673703330dcc7"
    $a12="691e16b9e4df16b70819d1f6cd9fc1774b62662dfb6b84bcbd7765445ceb74d1e3e325384276aaf6f822bddede03505a"
    $a13="014b8471ea2d98f7a19b1163cedf51d8a1c870cd09fa9fa6fb02b7aab25e2d9e8261f12edd43b8b8df892c93a4829dfd"
    $a14="5c24134fe6a8a72a061c157f7191dcb3dc02d203cb69ae5d1ea418adb64746fb6a4378ac307cf45978a1f3d536ad8a29"
    $a15="5c24134fe6a8a72a061c157f7191dcb3dc02d203cb69ae5d1ea418adb64746fb6a4378ac307cf45978a1f3d536ad8a29"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}