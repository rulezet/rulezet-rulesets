rule Disk2vhd
{
    meta:
        description = "Detection patterns for the tool 'Disk2vhd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disk2vhd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = ">Disk to VHD converter<" nocase ascii wide
                        $string2 = ">Disk2vhd<" nocase ascii wide
                        $string3 = /disk2vhd\.exe/ nocase ascii wide
                        $string4 = /Disk2vhd\.zip/ nocase ascii wide
                        $string5 = /disk2vhd64\.exe/ nocase ascii wide

    condition:
        any of them
}