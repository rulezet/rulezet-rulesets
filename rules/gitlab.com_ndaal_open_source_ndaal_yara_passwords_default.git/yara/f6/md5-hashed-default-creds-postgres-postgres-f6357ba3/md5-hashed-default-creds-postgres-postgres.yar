rule md5_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="bed128365216c019988915ed3add75fb"
    $a5="3d36562899c388a7ed9c40dc5c2dbf07"
    $a6="202cb962ac59075b964b07152d234b70"
    $a7="e8a48653851e28c69d0506508fb27fc5"
    $a8="21232f297a57a5a743894a0e4a801fc3"
    $a9="e8a48653851e28c69d0506508fb27fc5"
    $a10="59548977279905234b7ed3b1710837f2"
    $a11="e8a48653851e28c69d0506508fb27fc5"
    $a12="5f4dcc3b5aa765d61d8327deb882cf99"
    $a13="e8a48653851e28c69d0506508fb27fc5"
    $a14="e8a48653851e28c69d0506508fb27fc5"
    $a15="e8a48653851e28c69d0506508fb27fc5"
    $a16="86d0eb9b4f483c36fd48fca91211b5b1"
    $a17="e8a48653851e28c69d0506508fb27fc5"
    $a18="f89f124c0b230be9557c714912ee3320"
    $a19="e8a48653851e28c69d0506508fb27fc5"
    $a20="f89f124c0b230be9557c714912ee3320"
    $a21="21232f297a57a5a743894a0e4a801fc3"
    $a22="25df3104c0d6f0c1abd9c97bf6910771"
    $a23="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}