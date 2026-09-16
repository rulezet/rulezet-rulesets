rule rule_netscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netscan"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_netscan_greyware_tool_keyword = /\/netscan\.exe/ nocase ascii wide
                        $string2_netscan_greyware_tool_keyword = /\\netscan\.exe/ nocase ascii wide
                        $string3_netscan_greyware_tool_keyword = /\\netscan\.lic/ nocase ascii wide
                        $string4_netscan_greyware_tool_keyword = /\\netscan\.xml/ nocase ascii wide
                        $string5_netscan_greyware_tool_keyword = /\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
                        $string6_netscan_greyware_tool_keyword = /netscan_setup\.exe/ nocase ascii wide

    condition:
        any of them
}