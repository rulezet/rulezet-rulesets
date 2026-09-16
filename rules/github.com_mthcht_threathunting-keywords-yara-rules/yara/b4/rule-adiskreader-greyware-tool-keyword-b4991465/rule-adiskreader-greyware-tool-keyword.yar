rule rule_adiskreader_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adiskreader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adiskreader"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adiskreader_greyware_tool_keyword = "# adiskreader " nocase ascii wide
                        $string2_adiskreader_greyware_tool_keyword = /\\adiskreader\\/ nocase ascii wide
                        $string3_adiskreader_greyware_tool_keyword = /adiskreader\.disks\.raw/ nocase ascii wide
                        $string4_adiskreader_greyware_tool_keyword = /adiskreader\.disks\.vhdx/ nocase ascii wide

    condition:
        any of them
}