rule rule_Disk2vhd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Disk2vhd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disk2vhd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Disk2vhd_greyware_tool_keyword = ">Disk to VHD converter<" nocase ascii wide
                        $string2_Disk2vhd_greyware_tool_keyword = ">Disk2vhd<" nocase ascii wide
                        $string3_Disk2vhd_greyware_tool_keyword = /disk2vhd\.exe/ nocase ascii wide
                        $string4_Disk2vhd_greyware_tool_keyword = /Disk2vhd\.zip/ nocase ascii wide
                        $string5_Disk2vhd_greyware_tool_keyword = /disk2vhd64\.exe/ nocase ascii wide

    condition:
        any of them
}