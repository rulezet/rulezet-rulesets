rule rule_SamDumpCable_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SamDumpCable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SamDumpCable"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SamDumpCable_offensive_tool_keyword = "1337OMGsam" nocase ascii wide
                        $string2_SamDumpCable_offensive_tool_keyword = "1337OMGsys" nocase ascii wide
                        $string3_SamDumpCable_offensive_tool_keyword = "cgBlAGcAIABzAGEAdgBlACAAaABrAGwAbQBcAHMAYQBtACAAMQ" nocase ascii wide
                        $string4_SamDumpCable_offensive_tool_keyword = /OMGdump\.zip/ nocase ascii wide
                        $string5_SamDumpCable_offensive_tool_keyword = /reg\ssave\shklm\\sam\s1337/ nocase ascii wide
                        $string6_SamDumpCable_offensive_tool_keyword = /reg\ssave\shklm\\system\s1337/ nocase ascii wide

    condition:
        any of them
}