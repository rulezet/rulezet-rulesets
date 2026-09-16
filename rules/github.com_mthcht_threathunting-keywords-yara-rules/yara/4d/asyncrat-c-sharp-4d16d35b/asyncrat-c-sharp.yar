rule AsyncRAT_C_Sharp
{
    meta:
        description = "Detection patterns for the tool 'AsyncRAT-C-Sharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AsyncRAT-C-Sharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/AsyncRAT-C%23" nocase ascii wide
                        $string2 = "/AsyncRAT-C-Sharp" nocase ascii wide
                        $string3 = /\\AsyncRAT\\/ nocase ascii wide
                        $string4 = /\\Plugins\\RemoteCamera\.dll/ nocase ascii wide
                        $string5 = /\\Plugins\\RemoteDesktop\.dll/ nocase ascii wide
                        $string6 = "0DE8DA5D-061D-4649-8A56-48729CF1F789" nocase ascii wide
                        $string7 = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
                        $string8 = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
                        $string9 = "AsyncRAT  Simple RAT" nocase ascii wide
                        $string10 = "AsyncRAT Server" nocase ascii wide
                        $string11 = /AsyncRAT\.exe/ nocase ascii wide
                        $string12 = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
                        $string13 = "Hp6kvaq9BCyI" nocase ascii wide
                        $string14 = /User\-Agent.{0,1000}NIKMOK/ nocase ascii wide

    condition:
        any of them
}