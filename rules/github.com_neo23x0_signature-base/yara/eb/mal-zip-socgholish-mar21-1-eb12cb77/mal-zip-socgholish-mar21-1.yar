rule MAL_ZIP_SocGholish_Mar21_1 : zip js socgholish {
    meta:
        description = "Triggers on small zip files with typical SocGholish JS files in it"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
        hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
        hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
        id = "da35eefd-b34d-59cd-8afc-da9c78ace96e"
    strings:
        $a1 = /\.[a-z0-9]{6}\.js/ ascii
        $a2 = "Chrome" ascii
        $a3 = "Opera" ascii

        $b1 = "Firefox.js" ascii
        $b2 = "Edge.js" ascii
    condition:
        uint16(0) == 0x4b50 and filesize < 1600 and (
            2 of ($a*) or
            any of ($b*)
        )
}