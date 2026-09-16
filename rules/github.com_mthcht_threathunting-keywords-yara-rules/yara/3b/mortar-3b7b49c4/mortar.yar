rule mortar
{
    meta:
        description = "Detection patterns for the tool 'mortar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mortar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/encryptor\s\-f\s.{0,1000}\.exe/
                        $string2 = /\/mimikatz\.enc/ nocase ascii wide
                        $string3 = /\/mortar\.git/ nocase ascii wide
                        $string4 = "/mortar/releases/download/v2/encryptor" nocase ascii wide
                        $string5 = "/mortar/releases/download/v2/encryptor" nocase ascii wide
                        $string6 = /\/mortar\-loader\.html/ nocase ascii wide
                        $string7 = /\\\\pipe\\\\moj_ML_ntsvcs/ nocase ascii wide
                        $string8 = /\\\\pipe\\\\MyNamePipe/ nocase ascii wide
                        $string9 = /\\mortar\\Lib\\shell_loader\.pas/ nocase ascii wide
                        $string10 = /\\mortar\-loader\.html/ nocase ascii wide
                        $string11 = /\\pipe\\moj_ML_ntsvcs\s/ nocase ascii wide
                        $string12 = "0xsp-SRD/mortar" nocase ascii wide
                        $string13 = "0xsp-SRD/mortar" nocase ascii wide
                        $string14 = "411305d5a0aac7535dc0b676e880c689f254f270f402ec98e395a322996f75da" nocase ascii wide
                        $string15 = "ac77cefd856217e33d5acc730ea62c1a63e77a7a2fdd587d6d9bbfcea3e4da1d" nocase ascii wide
                        $string16 = /cmd\.exe\s\/c\srundll32\.exe\sagressor\.dll.{0,1000}stealth/ nocase ascii wide
                        $string17 = /deliver\.exe\s\-d\s\-c\s.{0,1000}\s\-f.{0,1000}\.enc/ nocase ascii wide
                        $string18 = /deliver\.exe\s\-d\s\-f\s.{0,1000}\.enc/ nocase ascii wide
                        $string19 = /encryptor\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.enc/ nocase ascii wide
                        $string20 = "f585b5225e1165fbeea3219ed3ce74988c60801831d5b7b1b2cc0bec1e4e4793" nocase ascii wide
                        $string21 = /mortar\-loader\.html/ nocase ascii wide
                        $string22 = /mortar\-main\.zip/ nocase ascii wide
                        $string23 = /rundll32\.exe\sagressor\.dll.{0,1000}dec/ nocase ascii wide

    condition:
        any of them
}