rule attrib
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\attrib\.exe.{0,1000}\s\+H\s/ nocase ascii wide
                        $string2 = /attrib\s.{0,1000}\.rdp\s\-s\s\-h/ nocase ascii wide
                        $string3 = /attrib\s\+R\s\+S\s\+H\sC\:\\WINDOWS\\scvhost\.exe/ nocase ascii wide
                        $string4 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
                        $string5 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\users\\Public\\/ nocase ascii wide
                        $string6 = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
                        $string7 = /attrib\sdesktop\.ini\s\+s\s\+h\s\+r/ nocase ascii wide
                        $string8 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\explorer\.exe/ nocase ascii wide
                        $string9 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\System32\\explorer\.exe/ nocase ascii wide
                        $string10 = "attrib -s -h %userprofile%" nocase ascii wide
                        $string11 = /attrib\s\-s\s\-h\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
                        $string12 = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
                        $string13 = /echo\sCLSID\=\{88C6C381\-2E85\-11D0\-94DE\-444553540000\}\s\>\>\sdesktop\.ini/ nocase ascii wide
                        $string14 = /echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini/ nocase ascii wide

    condition:
        any of them
}