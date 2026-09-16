rule EventCleaner
{
    meta:
        description = "Detection patterns for the tool 'EventCleaner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EventCleaner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/EventCleaner\.cpp/ nocase ascii wide
                        $string2 = /\/EventCleaner\.exe/ nocase ascii wide
                        $string3 = /\/EventCleaner\.git/ nocase ascii wide
                        $string4 = /\[\!\]\sinject\sdll\sinto\slog\sprocess\sfailure\s/ nocase ascii wide
                        $string5 = /\[\+\]\sdelete\ssingle\sevent\slog\ssucc/ nocase ascii wide
                        $string6 = /\[\+\]\ssecurity\sevtx\sfile\shandle\sunlock\ssucc/ nocase ascii wide
                        $string7 = /\\\\\.\\\\pipe\\\\kangaroo/ nocase ascii wide
                        $string8 = /\\EventCleaner\.cpp/ nocase ascii wide
                        $string9 = /\\EventCleaner\.exe/ nocase ascii wide
                        $string10 = /\\EventCleaner\.log/ nocase ascii wide
                        $string11 = /\\EventCleaner\.pdb/ nocase ascii wide
                        $string12 = /\\EventCleaner\.sln/ nocase ascii wide
                        $string13 = /\\EventCleaner\-master/ nocase ascii wide
                        $string14 = "0A2B3F8A-EDC2-48B5-A5FC-DE2AC57C8990" nocase ascii wide
                        $string15 = "D8A76296-A666-46C7-9CA0-254BA97E3B7C" nocase ascii wide
                        $string16 = "eventcleaner closehandle" nocase ascii wide
                        $string17 = "eventcleaner suspend" nocase ascii wide
                        $string18 = /EventCleaner\.exe\s/ nocase ascii wide
                        $string19 = /EventCleaner\.iobj/ nocase ascii wide
                        $string20 = /EventCleaner\\Debug\\/ nocase ascii wide
                        $string21 = /net\sstop\s\\\\"windows\sevent\slog\\\\"/ nocase ascii wide
                        $string22 = "QAX-A-Team/EventCleaner" nocase ascii wide

    condition:
        any of them
}