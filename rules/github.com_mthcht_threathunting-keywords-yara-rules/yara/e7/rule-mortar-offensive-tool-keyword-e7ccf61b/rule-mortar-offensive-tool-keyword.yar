rule rule_mortar_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mortar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mortar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mortar_offensive_tool_keyword = /\.\/encryptor\s\-f\s.{0,1000}\.exe/
                        $string2_mortar_offensive_tool_keyword = /\/mimikatz\.enc/ nocase ascii wide
                        $string3_mortar_offensive_tool_keyword = /\/mortar\.git/ nocase ascii wide
                        $string4_mortar_offensive_tool_keyword = "/mortar/releases/download/v2/encryptor" nocase ascii wide
                        $string5_mortar_offensive_tool_keyword = "/mortar/releases/download/v2/encryptor" nocase ascii wide
                        $string6_mortar_offensive_tool_keyword = /\/mortar\-loader\.html/ nocase ascii wide
                        $string7_mortar_offensive_tool_keyword = /\\\\pipe\\\\moj_ML_ntsvcs/ nocase ascii wide
                        $string8_mortar_offensive_tool_keyword = /\\\\pipe\\\\MyNamePipe/ nocase ascii wide
                        $string9_mortar_offensive_tool_keyword = /\\mortar\\Lib\\shell_loader\.pas/ nocase ascii wide
                        $string10_mortar_offensive_tool_keyword = /\\mortar\-loader\.html/ nocase ascii wide
                        $string11_mortar_offensive_tool_keyword = /\\pipe\\moj_ML_ntsvcs\s/ nocase ascii wide
                        $string12_mortar_offensive_tool_keyword = "0xsp-SRD/mortar" nocase ascii wide
                        $string13_mortar_offensive_tool_keyword = "0xsp-SRD/mortar" nocase ascii wide
                        $string14_mortar_offensive_tool_keyword = "411305d5a0aac7535dc0b676e880c689f254f270f402ec98e395a322996f75da" nocase ascii wide
                        $string15_mortar_offensive_tool_keyword = "ac77cefd856217e33d5acc730ea62c1a63e77a7a2fdd587d6d9bbfcea3e4da1d" nocase ascii wide
                        $string16_mortar_offensive_tool_keyword = /cmd\.exe\s\/c\srundll32\.exe\sagressor\.dll.{0,1000}stealth/ nocase ascii wide
                        $string17_mortar_offensive_tool_keyword = /deliver\.exe\s\-d\s\-c\s.{0,1000}\s\-f.{0,1000}\.enc/ nocase ascii wide
                        $string18_mortar_offensive_tool_keyword = /deliver\.exe\s\-d\s\-f\s.{0,1000}\.enc/ nocase ascii wide
                        $string19_mortar_offensive_tool_keyword = /encryptor\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.enc/ nocase ascii wide
                        $string20_mortar_offensive_tool_keyword = "f585b5225e1165fbeea3219ed3ce74988c60801831d5b7b1b2cc0bec1e4e4793" nocase ascii wide
                        $string21_mortar_offensive_tool_keyword = /mortar\-loader\.html/ nocase ascii wide
                        $string22_mortar_offensive_tool_keyword = /mortar\-main\.zip/ nocase ascii wide
                        $string23_mortar_offensive_tool_keyword = /rundll32\.exe\sagressor\.dll.{0,1000}dec/ nocase ascii wide

    condition:
        any of them
}