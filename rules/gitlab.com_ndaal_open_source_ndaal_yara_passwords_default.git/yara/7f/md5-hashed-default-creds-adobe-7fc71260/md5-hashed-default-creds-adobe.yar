rule md5_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="02bd92faa38aaa6cc0ea75e59937a1ef"
    $a3="02bd92faa38aaa6cc0ea75e59937a1ef"
    $a4="294de3557d9d00b3d2d8a1e6aab028cf"
    $a5="294de3557d9d00b3d2d8a1e6aab028cf"
    $a6="bac7680036060d092d371672f311b50a"
    $a7="a56a94bf6b1c32f53d3f2524c42def08"
    $a8="a31405d272b94e5d12e9a52a665d3bfe"
    $a9="e66fde846efd7505dc42251c6ddc500d"
    $a10="345bef9bffa11e0945df1e03cfa0fb37"
    $a11="345bef9bffa11e0945df1e03cfa0fb37"
    $a12="0c5d82ccc18bdb8eadecf6b00acb34aa"
    $a13="0c5d82ccc18bdb8eadecf6b00acb34aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}