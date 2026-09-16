rule blake2b_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c029c24b2c89db037fbf8b04930569fd8422f7c0d62f36c8dae35d03332139e546a1126f6c75be43685598f48cefff1d05a3c74d804fcd5c0a53734cfb0bb862"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c"
    $a3="deeca6e590923ec4cf3b5f918a5720a77eaca97fb2accf6adf64fb755db53097bc4937ac9a127552fbc9a96baf7cb4f01f14b819abe90e294bb5fa3651ac2219"
    $a4="c029c24b2c89db037fbf8b04930569fd8422f7c0d62f36c8dae35d03332139e546a1126f6c75be43685598f48cefff1d05a3c74d804fcd5c0a53734cfb0bb862"
    $a5="53aac41318b6489226bd21fa781227d2f7f53d8f12e24d40009eac51a51ea992d8d9b8fee4670c061611c4ae72303b5979fa045ac0c8af529dc8639b86c1f7e4"
    $a6="0fddfe69251fd8b811a37bb45f8ef0c8485d3e60d84361d15701a5603b30cfcd572bd0bccd1e108dd697c7c53c492c188a42029b1b8a47c9ecf9ac311fc0a3e8"
    $a7="60fc84ffd21044734508297ababc41079d1bdcbe2bab0e29adb469b66f7a977367c11b7dbf76fe33bb29fd28f32f529443c37e0f4d0d1a9bd78321da6f09013d"
    $a8="49db7a7a6bea2cd893596c1aeebf733c91cf89d7fa0fcb7271dcd5ddc9d12aeebef3e297eb161f01784185ef43b275026737a55678a0798c34412dd4873a0841"
    $a9="4761e44a2a11a2020408369731b6fbd94156f23566c71d58714d6d74ba16bdf1f9cfcc1fb60a2c0e0c74f663e624afb164d570e0f9da04decb2453777adf5bb5"
    $a10="d40bf097cf03db84252294c2a19544fbc01970231f36dca2de944e48a8d8b945fe84158070b568af2f6094f07088bd57446524c56751a10965954e5bfeb6c5b4"
    $a11="d71ad83b9210f75c192aa12c709c9dcdcf6e768b17efc82863a1357d825fe02d10209c2190314607db8993d7d5cab59f94bf86082e1ecee589a4481a42e83eee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}