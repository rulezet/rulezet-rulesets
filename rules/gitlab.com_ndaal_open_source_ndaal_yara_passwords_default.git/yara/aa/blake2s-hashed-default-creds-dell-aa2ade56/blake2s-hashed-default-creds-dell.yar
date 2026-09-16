rule blake2s_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="345083deb54e99d43195872fa21882f4f0fa3453d3d031198f1b324a9449aa58"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="46b45e71bc37fb23c1db0aa227bed3a2b7fb45e69830331edb011a1c7ee36c5b"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="5230474dc1d57c362608192d4d5419f970eaae768488f0eb31ff516c1a58fa2f"
    $a9="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a10="34c9eda7c76c43f0dbe80aa71a87c709173327ab81f6a6159d4eabee624854f7"
    $a11="708109fb58c3df709b898c9b6dbe620816bc4f91f1c089b7e0acabd2acbcc4d7"
    $a12="85f788510c30939dd22bb14176b615d585b0d500e3e2bc6b2b4a581d0a821420"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="e74964bf0966ab850c05e184d2b4b2c6c23f75ea831b24a2956ef66c4b64e660"
    $a15="15435fbf1b82e0ad687264f141a79e10ecc498c6b2e30d1f489e0561ba15b879"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}