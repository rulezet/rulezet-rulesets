rule netscan
{
    meta:
        description = "Detection patterns for the tool 'netscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netscan"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/netscan\.exe/ nocase ascii wide
                        $string2 = /\\netscan\.exe/ nocase ascii wide
                        $string3 = /\\netscan\.lic/ nocase ascii wide
                        $string4 = /\\netscan\.xml/ nocase ascii wide
                        $string5 = /\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
                        $string6 = /netscan_setup\.exe/ nocase ascii wide

    condition:
        any of them
}