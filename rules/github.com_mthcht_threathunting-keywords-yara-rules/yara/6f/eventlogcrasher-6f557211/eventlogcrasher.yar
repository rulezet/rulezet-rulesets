rule EventLogCrasher
{
    meta:
        description = "Detection patterns for the tool 'EventLogCrasher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventLogCrasher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sRegisterEventSourceW\(L\\"DESKTOP\-\.\.\.\\".{0,1000}\sL\\"1337/ nocase ascii wide
                        $string2 = /\/EventLogCrasher\.git/ nocase ascii wide
                        $string3 = /\\EventLogCrasher\\/ nocase ascii wide
                        $string4 = "corrupt data that was marshalled by Ndr64ConformantVaryingArrayMarshall" nocase ascii wide
                        $string5 = /eventlog_dos\.exe/ nocase ascii wide
                        $string6 = /EventLogCrasher\.exe/ nocase ascii wide
                        $string7 = "EventLogCrasher-main" nocase ascii wide
                        $string8 = "floesen/EventLogCrasher" nocase ascii wide

    condition:
        any of them
}