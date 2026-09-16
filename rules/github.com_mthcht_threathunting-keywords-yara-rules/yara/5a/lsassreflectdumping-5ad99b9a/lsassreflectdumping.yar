rule LsassReflectDumping
{
    meta:
        description = "Detection patterns for the tool 'LsassReflectDumping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LsassReflectDumping"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LsassReflectDumping\.git/ nocase ascii wide
                        $string2 = /\/ReflectDump\.exe/ nocase ascii wide
                        $string3 = /\\ReflectDump\.exe/ nocase ascii wide
                        $string4 = /\\ReflectDump\.vcxproj/ nocase ascii wide
                        $string5 = "2677e9423aa9c338fa85cc819fa88b20262f6838f7323da6513c80a0c9c05803" nocase ascii wide
                        $string6 = "73c6754604666d7e05ed07db7ebc79fa3fe8d85cb049132c1b7b7d33181a70e6" nocase ascii wide
                        $string7 = "b7ac3213e10a169498f8e34b434aced491debb07d2e82c59c86f8c0c6581cf51" nocase ascii wide
                        $string8 = "e58f5924f64e96f3f84ef788dde5fc6699f91086a8fbc4797065670a37a3cbcd" nocase ascii wide
                        $string9 = "edd9d1b4-27f7-424a-aa21-794b19231741" nocase ascii wide
                        $string10 = "Offensive-Panda/LsassReflectDumping" nocase ascii wide
                        $string11 = /Succesfully\sMirrored\sto\slsass\.exe/ nocase ascii wide
                        $string12 = "Successfully created dump of the forked process" nocase ascii wide
                        $string13 = "Successfully dumped lsass process" nocase ascii wide

    condition:
        any of them
}