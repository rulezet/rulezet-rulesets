rule SamDumpCable
{
    meta:
        description = "Detection patterns for the tool 'SamDumpCable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SamDumpCable"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "1337OMGsam" nocase ascii wide
                        $string2 = "1337OMGsys" nocase ascii wide
                        $string3 = "cgBlAGcAIABzAGEAdgBlACAAaABrAGwAbQBcAHMAYQBtACAAMQ" nocase ascii wide
                        $string4 = /OMGdump\.zip/ nocase ascii wide
                        $string5 = /reg\ssave\shklm\\sam\s1337/ nocase ascii wide
                        $string6 = /reg\ssave\shklm\\system\s1337/ nocase ascii wide

    condition:
        any of them
}