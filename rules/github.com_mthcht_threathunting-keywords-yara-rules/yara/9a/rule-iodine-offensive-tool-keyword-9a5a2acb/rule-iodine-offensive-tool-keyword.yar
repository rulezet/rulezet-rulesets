rule rule_iodine_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'iodine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iodine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_iodine_offensive_tool_keyword = " install iodine"
                        $string2_iodine_offensive_tool_keyword = /\.\/iodined/
                        $string3_iodine_offensive_tool_keyword = /\/iodine\-.{0,1000}\-windows\.zip/ nocase ascii wide
                        $string4_iodine_offensive_tool_keyword = /\/iodine\.exe/ nocase ascii wide
                        $string5_iodine_offensive_tool_keyword = /\/iodine\.git/ nocase ascii wide
                        $string6_iodine_offensive_tool_keyword = "/iodine-master/" nocase ascii wide
                        $string7_iodine_offensive_tool_keyword = "/ionide "
                        $string8_iodine_offensive_tool_keyword = "/sysconfig/iodine-server"
                        $string9_iodine_offensive_tool_keyword = "/unstable/net/iodine" nocase ascii wide
                        $string10_iodine_offensive_tool_keyword = /\\iodine\-.{0,1000}\-windows\.zip/ nocase ascii wide
                        $string11_iodine_offensive_tool_keyword = /\\iodine\.exe/ nocase ascii wide
                        $string12_iodine_offensive_tool_keyword = /\\iodine\-master\\/ nocase ascii wide
                        $string13_iodine_offensive_tool_keyword = "00cce05cfc7ac3c284be62e98c8ffb25" nocase ascii wide
                        $string14_iodine_offensive_tool_keyword = "3318d1dd3fcab5f3e4ab3cc5b690a3f4" nocase ascii wide
                        $string15_iodine_offensive_tool_keyword = "3e3fcf025697ee80f044716eee053848" nocase ascii wide
                        $string16_iodine_offensive_tool_keyword = "58d82bca11a41a01d0ddfa7d105e6a48" nocase ascii wide
                        $string17_iodine_offensive_tool_keyword = "5bb0b56e047e1453a3695ec0b9478b84" nocase ascii wide
                        $string18_iodine_offensive_tool_keyword = "6952343cc4614857f83dbb81247871e7" nocase ascii wide
                        $string19_iodine_offensive_tool_keyword = "6f2a53476cbc09bbffe7e07d6e9dd19d" nocase ascii wide
                        $string20_iodine_offensive_tool_keyword = "795f2e9d0314898ba5a63bd1fdc5fa18" nocase ascii wide
                        $string21_iodine_offensive_tool_keyword = "82d331f75a99d1547e0ccc3c3efd0a7a" nocase ascii wide
                        $string22_iodine_offensive_tool_keyword = "890f13ab9ee7ea722baf0ceb3ee561c0" nocase ascii wide
                        $string23_iodine_offensive_tool_keyword = "a15bb4faba020d217016fde6e231074a" nocase ascii wide
                        $string24_iodine_offensive_tool_keyword = "a201bc3c2d47775b39cd90b32eb390e7" nocase ascii wide
                        $string25_iodine_offensive_tool_keyword = "af2d9062b7788fc47385d8c6c645dfa0" nocase ascii wide
                        $string26_iodine_offensive_tool_keyword = "Aw8KAw4LDgvZDgLUz2rLC2rPBMC" nocase ascii wide
                        $string27_iodine_offensive_tool_keyword = "b18aca1b9e2a9e72cb77960c355d288b"
                        $string28_iodine_offensive_tool_keyword = "bin/iodine" nocase ascii wide
                        $string29_iodine_offensive_tool_keyword = "c01fb08dabbd24b151fe5dfbb0742f7a" nocase ascii wide
                        $string30_iodine_offensive_tool_keyword = "cdaee04229c5aefdb806af27910f34d3" nocase ascii wide
                        $string31_iodine_offensive_tool_keyword = "dfbc5037fe0229e15f6f15775117aef5" nocase ascii wide
                        $string32_iodine_offensive_tool_keyword = "f2a64b4fce0d07eafded5c2125d7d80b" nocase ascii wide
                        $string33_iodine_offensive_tool_keyword = "fdbf3b81cd69caf5230d76a8b039fd99" nocase ascii wide
                        $string34_iodine_offensive_tool_keyword = /https\:\/\/code\.kryo\.se\/iodine\/iodine\-/ nocase ascii wide
                        $string35_iodine_offensive_tool_keyword = "iodine -"
                        $string36_iodine_offensive_tool_keyword = "iodine -f "
                        $string37_iodine_offensive_tool_keyword = "iodine IP over DNS tunneling server"
                        $string38_iodine_offensive_tool_keyword = "iodine -v"
                        $string39_iodine_offensive_tool_keyword = "iodined -"
                        $string40_iodine_offensive_tool_keyword = "iodined -c"
                        $string41_iodine_offensive_tool_keyword = "iodined -f "
                        $string42_iodine_offensive_tool_keyword = "iodined -v"
                        $string43_iodine_offensive_tool_keyword = "iodine-latest/"
                        $string44_iodine_offensive_tool_keyword = /iodine\-latest\-android\.zip/ nocase ascii wide
                        $string45_iodine_offensive_tool_keyword = "iodine-latest-win32" nocase ascii wide
                        $string46_iodine_offensive_tool_keyword = "iodine-latest-windows" nocase ascii wide
                        $string47_iodine_offensive_tool_keyword = /iodine\-server\.service/ nocase ascii wide
                        $string48_iodine_offensive_tool_keyword = "iodinetestingtesting" nocase ascii wide
                        $string49_iodine_offensive_tool_keyword = "ionided " nocase ascii wide
                        $string50_iodine_offensive_tool_keyword = "nfxwi0lomv0gk21unfxgo3dfon0gs1th" nocase ascii wide
                        $string51_iodine_offensive_tool_keyword = /silly\.host\.of\.iodine\.code\.kryo\.se/ nocase ascii wide
                        $string52_iodine_offensive_tool_keyword = "sudo iodine "
                        $string53_iodine_offensive_tool_keyword = /test\-iodine\.log/ nocase ascii wide
                        $string54_iodine_offensive_tool_keyword = "yarrick/iodine" nocase ascii wide

    condition:
        any of them
}