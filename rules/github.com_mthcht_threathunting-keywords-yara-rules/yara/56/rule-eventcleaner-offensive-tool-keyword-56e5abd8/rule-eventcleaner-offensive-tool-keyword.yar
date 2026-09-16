rule rule_EventCleaner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EventCleaner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventCleaner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EventCleaner_offensive_tool_keyword = /\/EventCleaner\.cpp/ nocase ascii wide
                        $string2_EventCleaner_offensive_tool_keyword = /\/EventCleaner\.exe/ nocase ascii wide
                        $string3_EventCleaner_offensive_tool_keyword = /\/EventCleaner\.git/ nocase ascii wide
                        $string4_EventCleaner_offensive_tool_keyword = /\[\!\]\sinject\sdll\sinto\slog\sprocess\sfailure\s/ nocase ascii wide
                        $string5_EventCleaner_offensive_tool_keyword = /\[\+\]\sdelete\ssingle\sevent\slog\ssucc/ nocase ascii wide
                        $string6_EventCleaner_offensive_tool_keyword = /\[\+\]\ssecurity\sevtx\sfile\shandle\sunlock\ssucc/ nocase ascii wide
                        $string7_EventCleaner_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\kangaroo/ nocase ascii wide
                        $string8_EventCleaner_offensive_tool_keyword = /\\EventCleaner\.cpp/ nocase ascii wide
                        $string9_EventCleaner_offensive_tool_keyword = /\\EventCleaner\.exe/ nocase ascii wide
                        $string10_EventCleaner_offensive_tool_keyword = /\\EventCleaner\.log/ nocase ascii wide
                        $string11_EventCleaner_offensive_tool_keyword = /\\EventCleaner\.pdb/ nocase ascii wide
                        $string12_EventCleaner_offensive_tool_keyword = /\\EventCleaner\.sln/ nocase ascii wide
                        $string13_EventCleaner_offensive_tool_keyword = /\\EventCleaner\-master/ nocase ascii wide
                        $string14_EventCleaner_offensive_tool_keyword = "0A2B3F8A-EDC2-48B5-A5FC-DE2AC57C8990" nocase ascii wide
                        $string15_EventCleaner_offensive_tool_keyword = "D8A76296-A666-46C7-9CA0-254BA97E3B7C" nocase ascii wide
                        $string16_EventCleaner_offensive_tool_keyword = "eventcleaner closehandle" nocase ascii wide
                        $string17_EventCleaner_offensive_tool_keyword = "eventcleaner suspend" nocase ascii wide
                        $string18_EventCleaner_offensive_tool_keyword = /EventCleaner\.exe\s/ nocase ascii wide
                        $string19_EventCleaner_offensive_tool_keyword = /EventCleaner\.iobj/ nocase ascii wide
                        $string20_EventCleaner_offensive_tool_keyword = /EventCleaner\\Debug\\/ nocase ascii wide
                        $string21_EventCleaner_offensive_tool_keyword = /net\sstop\s\\\\"windows\sevent\slog\\\\"/ nocase ascii wide
                        $string22_EventCleaner_offensive_tool_keyword = "QAX-A-Team/EventCleaner" nocase ascii wide

    condition:
        any of them
}