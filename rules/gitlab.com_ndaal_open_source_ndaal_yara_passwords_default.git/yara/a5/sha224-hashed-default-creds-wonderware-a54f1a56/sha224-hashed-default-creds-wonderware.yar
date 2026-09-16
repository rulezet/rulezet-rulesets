rule sha224_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1db3b71b576e4e0834aa48d06e6181bde83ab1b96b688b194c427858"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="63f04a68a327b6932ed60c43110bd8ed0e39c14b1bd12916a466dd43"
    $a3="5dd84d598e1fbf855a6de10d3223bc5e6bd714b99581aa026573c85e"
    $a4="63f04a68a327b6932ed60c43110bd8ed0e39c14b1bd12916a466dd43"
    $a5="a9dfe45f992cbd82199e9e2db80f1590a1ca2a156e39a072870ce3cf"
    $a6="e7722bf002f04a50aa431e9d2509be7a28079ed8aee30961cc51c16c"
    $a7="e0fba95c78422a27da775fac5ffa7b12595706af743a972287525dff"
    $a8="130fdb05e9a014dc6377a02f571d914636b011dcc3faa5aacdd49acc"
    $a9="130fdb05e9a014dc6377a02f571d914636b011dcc3faa5aacdd49acc"
    $a10="fc8d606085bed264d006738011b0e22fb4ea894d04b0fcba0d006b1b"
    $a11="a71654a85e969f14c3b640d5ffb80839798f781da5cc48b56e6b4069"
    $a12="6f44726875df2af55ec5aaf012405225fc0f800c2ed5f389cb0a2d98"
    $a13="6f44726875df2af55ec5aaf012405225fc0f800c2ed5f389cb0a2d98"
    $a14="56290555e3f7818843439ad1388d385bb6330a856d2e9885933b1b6b"
    $a15="81e3cc97d51e5a49aaefea6ad781b08e4d073e3ce710d7da8a240d65"
    $a16="459bb46d2724b116ccc41f91d996f4e45309852a7b0468f79e03924a"
    $a17="459bb46d2724b116ccc41f91d996f4e45309852a7b0468f79e03924a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}