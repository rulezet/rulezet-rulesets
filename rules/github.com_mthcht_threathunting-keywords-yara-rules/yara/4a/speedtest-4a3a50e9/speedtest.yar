rule speedtest
{
    meta:
        description = "Detection patterns for the tool 'speedtest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "speedtest"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/raw\/main\/speedtest\.exe/ nocase ascii wide
                        $string2 = /\/raw\/master\/speedtest\.exe/ nocase ascii wide
                        $string3 = /\\speedtest\.exe\s\-\-accept\-license/ nocase ascii wide
                        $string4 = /\\speedtest\.exe\\"\s\-\-accept\-license/ nocase ascii wide
                        $string5 = "dffc17b4b0f9c841d94802e2c9578758dbb52ca1ab967a506992c26aabecc43a" nocase ascii wide
                        $string6 = /ProgramData\\speedtest\.exe/ nocase ascii wide
                        $string7 = /ProgramData\\SpeedtestCLI/ nocase ascii wide

    condition:
        any of them
}