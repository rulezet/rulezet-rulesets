rule adiskreader
{
    meta:
        description = "Detection patterns for the tool 'adiskreader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adiskreader"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "# adiskreader " nocase ascii wide
                        $string2 = /\\adiskreader\\/ nocase ascii wide
                        $string3 = /adiskreader\.disks\.raw/ nocase ascii wide
                        $string4 = /adiskreader\.disks\.vhdx/ nocase ascii wide

    condition:
        any of them
}