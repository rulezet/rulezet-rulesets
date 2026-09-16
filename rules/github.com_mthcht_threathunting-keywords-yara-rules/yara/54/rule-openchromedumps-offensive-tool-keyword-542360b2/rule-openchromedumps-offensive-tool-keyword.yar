rule rule_OpenChromeDumps_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OpenChromeDumps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OpenChromeDumps"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OpenChromeDumps_offensive_tool_keyword = /\\openchromedumps\.exe/ nocase ascii wide
                        $string2_OpenChromeDumps_offensive_tool_keyword = /\\openChromeDumps\.pdb/ nocase ascii wide
                        $string3_OpenChromeDumps_offensive_tool_keyword = "0b9219328ebf065db9b26c9a189d72c7d0d9c39eb35e9fd2a5fefa54a7f853e4" nocase ascii wide
                        $string4_OpenChromeDumps_offensive_tool_keyword = "1c543ea5c50ef8b0b42f835970fa5f553c2ae5c308d2692b51fb476173653cb3" nocase ascii wide
                        $string5_OpenChromeDumps_offensive_tool_keyword = "99e25d4179b7a0419d07f671ab86f25a86582e256e0862fc431eb7f93cfb3ced" nocase ascii wide
                        $string6_OpenChromeDumps_offensive_tool_keyword = /openChromeDumpsHTML\.exe/ nocase ascii wide

    condition:
        any of them
}