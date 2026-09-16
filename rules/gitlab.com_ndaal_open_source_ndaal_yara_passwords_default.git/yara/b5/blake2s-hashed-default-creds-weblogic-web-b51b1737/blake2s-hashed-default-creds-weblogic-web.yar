rule blake2s_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9b48bb4dfc4882ff7b733062973eb14d8d78c74a3aefd73864be13724d75f662"
    $a1="9b48bb4dfc4882ff7b733062973eb14d8d78c74a3aefd73864be13724d75f662"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a6="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a7="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
    $a8="d8a1bcdcb4d9622c81582515341ca59311cca927000b61143955aff84c064f95"
    $a9="d8a1bcdcb4d9622c81582515341ca59311cca927000b61143955aff84c064f95"
    $a10="1ba366171bfdf505601934358c61e7d989cd2751271d1fd633ec794d8c3b89ea"
    $a11="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a12="2b3e97675aeca50cd4e00252abc5d8cb734540cd86db41fd5ff99d2e37275575"
    $a13="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a14="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a15="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a16="d232ec25aa77ee8c561090fd6bf285d543aea9545c71753ed972201271fc9cdd"
    $a17="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a18="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a19="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a20="b2dcc1b51d415a097d7c2e5432cb95775b25c67e7e1791cebe6b5a974b9c3c7b"
    $a21="b2dcc1b51d415a097d7c2e5432cb95775b25c67e7e1791cebe6b5a974b9c3c7b"
    $a22="8fdca6949ee5b2063746581b0d8ca89926e163660fc99afbb731c6d683f1097b"
    $a23="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
    $a24="d232ec25aa77ee8c561090fd6bf285d543aea9545c71753ed972201271fc9cdd"
    $a25="eb9a4c3626871a0b20c65170b823b5e26a50e2a6014956dace0350460d24a65b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}