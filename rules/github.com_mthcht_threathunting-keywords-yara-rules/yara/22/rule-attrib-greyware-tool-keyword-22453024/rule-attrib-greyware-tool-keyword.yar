rule rule_attrib_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_attrib_greyware_tool_keyword = /\\attrib\.exe.{0,1000}\s\+H\s/ nocase ascii wide
                        $string2_attrib_greyware_tool_keyword = /attrib\s.{0,1000}\.rdp\s\-s\s\-h/ nocase ascii wide
                        $string3_attrib_greyware_tool_keyword = /attrib\s\+R\s\+S\s\+H\sC\:\\WINDOWS\\scvhost\.exe/ nocase ascii wide
                        $string4_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
                        $string5_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\users\\Public\\/ nocase ascii wide
                        $string6_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
                        $string7_attrib_greyware_tool_keyword = /attrib\sdesktop\.ini\s\+s\s\+h\s\+r/ nocase ascii wide
                        $string8_attrib_greyware_tool_keyword = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\explorer\.exe/ nocase ascii wide
                        $string9_attrib_greyware_tool_keyword = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\System32\\explorer\.exe/ nocase ascii wide
                        $string10_attrib_greyware_tool_keyword = "attrib -s -h %userprofile%" nocase ascii wide
                        $string11_attrib_greyware_tool_keyword = /attrib\s\-s\s\-h\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
                        $string12_attrib_greyware_tool_keyword = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
                        $string13_attrib_greyware_tool_keyword = /echo\sCLSID\=\{88C6C381\-2E85\-11D0\-94DE\-444553540000\}\s\>\>\sdesktop\.ini/ nocase ascii wide
                        $string14_attrib_greyware_tool_keyword = /echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini/ nocase ascii wide

    condition:
        any of them
}