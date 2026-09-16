rule rule_vncviewer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_vncviewer_greyware_tool_keyword = ">RealVNC<" nocase ascii wide
                        $string2_vncviewer_greyware_tool_keyword = ">UltraVNC VNCViewer<" nocase ascii wide
                        $string3_vncviewer_greyware_tool_keyword = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,1000}\.exe/ nocase ascii wide
                        $string4_vncviewer_greyware_tool_keyword = /RealVNC\.VNCViewer/ nocase ascii wide
                        $string5_vncviewer_greyware_tool_keyword = /vncviewer\s.{0,1000}\..{0,1000}\:5901/
                        $string6_vncviewer_greyware_tool_keyword = /VNCViewer\.exe/ nocase ascii wide

    condition:
        any of them
}