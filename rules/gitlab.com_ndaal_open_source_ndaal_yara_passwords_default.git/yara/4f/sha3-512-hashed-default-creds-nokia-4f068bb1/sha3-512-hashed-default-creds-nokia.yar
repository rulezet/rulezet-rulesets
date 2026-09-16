rule sha3_512_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a1="cc7b8225e921d98472b1fdc77a00ca8b2ae02cb6578a3b9e9e6bace00252311c1e3264df33426b3aa36dafc03d973bc5fdb38f1ce5de9283393d8c51a4183804"
    $a2="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a3="099fd622c3a5797b980360ab230600ad42ec392d25d68b715827211eca3e2971c9f445e8161ec80dd3c0e4a55d1bb82a5d0da8164b1f8816cbec43cdab8d4e59"
    $a4="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a5="8dab86975e5efa0a8f140e8a29b33ba232edeb8b2aaf2408f5fe1070fdaaad1795c227d58931a275777fe92e3c3fcef21b395f3b87384e9cfae5513c7685d889"
    $a6="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a7="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a8="29bdf6e37475a3019d6aaf797d7c015403b0596ebd26a307a6d9d2e02b2843d541853a00a77e7c43dd214682abe2f1c89ffd0a3b5a2622c4746bce84ce1a71b2"
    $a9="e53ad98cf3081f292dfaff1c5c9a2532dd4cf87c023d45ddfe3bbfecafdd60317f30d88d990cf02101a33dbefe4c29f0634ebd53b962bd91e9d4937f0f006c5e"
    $a10="f376c5f7052c441759b1667c4d80c125c7f5e377f6f0fbb9cc055cef1e0d237c8bc596fdb3d1ef696259b8c91fdb58406659e9eeb08cba614ddf77700891a741"
    $a11="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a12="ebb1f467a01dad7841e4db3a8495461a51d64d5b986f218dedaaa3e3c20a82e9f29ae0d3d4c2653d580d6e5062589a523f04912fe0cc3d760bbd029b78e5dad2"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a14="0a2a1719bf3ce682afdbedf3b23857818d526efbe7fcb372b31347c26239a0f916c398b7ad8dd0ee76e8e388604d0b0f925d5e913ad2d3165b9b35b3844cd5e6"
    $a15="efe4903d927ec614d4591348e0266bea1f74e798eba058dd8fa7ca685726c1d6d9575e450d5650a8610313f06c2835abdf73555abb3807789c5df8d913fe1107"
    $a16="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
    $a17="1c5dd0861a3e1d7368bd1c4e01eaa6624c30a4b1baa0abf5d033b424e5ec7b8a36fd98c12c1b4bb2dfba18228c3a56dc18d583ff34ac599bd26d682980f8429f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}