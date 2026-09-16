rule rule_AsyncRAT_C_Sharp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AsyncRAT-C-Sharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AsyncRAT-C-Sharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AsyncRAT_C_Sharp_offensive_tool_keyword = "/AsyncRAT-C%23" nocase ascii wide
                        $string2_AsyncRAT_C_Sharp_offensive_tool_keyword = "/AsyncRAT-C-Sharp" nocase ascii wide
                        $string3_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\AsyncRAT\\/ nocase ascii wide
                        $string4_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\Plugins\\RemoteCamera\.dll/ nocase ascii wide
                        $string5_AsyncRAT_C_Sharp_offensive_tool_keyword = /\\Plugins\\RemoteDesktop\.dll/ nocase ascii wide
                        $string6_AsyncRAT_C_Sharp_offensive_tool_keyword = "0DE8DA5D-061D-4649-8A56-48729CF1F789" nocase ascii wide
                        $string7_AsyncRAT_C_Sharp_offensive_tool_keyword = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
                        $string8_AsyncRAT_C_Sharp_offensive_tool_keyword = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
                        $string9_AsyncRAT_C_Sharp_offensive_tool_keyword = "AsyncRAT  Simple RAT" nocase ascii wide
                        $string10_AsyncRAT_C_Sharp_offensive_tool_keyword = "AsyncRAT Server" nocase ascii wide
                        $string11_AsyncRAT_C_Sharp_offensive_tool_keyword = /AsyncRAT\.exe/ nocase ascii wide
                        $string12_AsyncRAT_C_Sharp_offensive_tool_keyword = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
                        $string13_AsyncRAT_C_Sharp_offensive_tool_keyword = "Hp6kvaq9BCyI" nocase ascii wide
                        $string14_AsyncRAT_C_Sharp_offensive_tool_keyword = /User\-Agent.{0,1000}NIKMOK/ nocase ascii wide

    condition:
        any of them
}