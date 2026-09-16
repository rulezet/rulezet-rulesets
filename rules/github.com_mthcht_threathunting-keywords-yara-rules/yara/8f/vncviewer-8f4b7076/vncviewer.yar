rule vncviewer
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = ">RealVNC<" nocase ascii wide
                        $string2 = ">UltraVNC VNCViewer<" nocase ascii wide
                        $string3 = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,1000}\.exe/ nocase ascii wide
                        $string4 = /RealVNC\.VNCViewer/ nocase ascii wide
                        $string5 = /vncviewer\s.{0,1000}\..{0,1000}\:5901/
                        $string6 = /VNCViewer\.exe/ nocase ascii wide

    condition:
        any of them
}