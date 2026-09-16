rule blake2s_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a1="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a2="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a3="61b83c12ccabd0333a492ba2d826cbeae8d9b2febdc369da09614c29342a2bd1"
    $a4="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a6="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a7="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a8="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a9="95c4b7287769151aa0fab9550000b24a35c29a962b1b83796f6436320331552e"
    $a10="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a11="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a12="266486ffaaf21e92ff887377539a51996333d2faeecdaf6cc49bd8ef7cb3ae8a"
    $a13="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a14="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a15="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a16="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a17="c433cfbbb003de680514002697229db8740b3820a4ff914f6e1ea24f953a5730"
    $a18="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a19="21853332c749d7bce769b738faab633854cd5f380edbbed56a7baa958e637125"
    $a20="fe705ddd07bd5b4759ed9582a793e69b923f0cebd6653d4bb639fd9bcb400783"
    $a21="070a3aacfe77889883b651df90e9ed8e88a8d93d9cf91391ab321f60a8706862"
    $a22="934804255c453972da99bcdec2e4d99aad2c277bc7469bb335d4a835cd32e529"
    $a23="fac3810507075ee8b15f29b738065feb912e349f9826411cb5507e00073c6cd6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}