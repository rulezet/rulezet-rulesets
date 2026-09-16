rule rule_EventLogCrasher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EventLogCrasher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventLogCrasher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EventLogCrasher_offensive_tool_keyword = /\sRegisterEventSourceW\(L\\"DESKTOP\-\.\.\.\\".{0,1000}\sL\\"1337/ nocase ascii wide
                        $string2_EventLogCrasher_offensive_tool_keyword = /\/EventLogCrasher\.git/ nocase ascii wide
                        $string3_EventLogCrasher_offensive_tool_keyword = /\\EventLogCrasher\\/ nocase ascii wide
                        $string4_EventLogCrasher_offensive_tool_keyword = "corrupt data that was marshalled by Ndr64ConformantVaryingArrayMarshall" nocase ascii wide
                        $string5_EventLogCrasher_offensive_tool_keyword = /eventlog_dos\.exe/ nocase ascii wide
                        $string6_EventLogCrasher_offensive_tool_keyword = /EventLogCrasher\.exe/ nocase ascii wide
                        $string7_EventLogCrasher_offensive_tool_keyword = "EventLogCrasher-main" nocase ascii wide
                        $string8_EventLogCrasher_offensive_tool_keyword = "floesen/EventLogCrasher" nocase ascii wide

    condition:
        any of them
}