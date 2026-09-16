rule rule_SharpRDPThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpRDPThief_offensive_tool_keyword = /\sRDPHook\.dll/ nocase ascii wide
                        $string2_SharpRDPThief_offensive_tool_keyword = /\/RDPHook\.dll/ nocase ascii wide
                        $string3_SharpRDPThief_offensive_tool_keyword = /\/SharpRDPThief\.git/ nocase ascii wide
                        $string4_SharpRDPThief_offensive_tool_keyword = /\\RDPHook\.dll/ nocase ascii wide
                        $string5_SharpRDPThief_offensive_tool_keyword = /\\SharpRDPThief\\/ nocase ascii wide
                        $string6_SharpRDPThief_offensive_tool_keyword = "20B3AA84-9CA7-43E5-B0CD-8DBA5091DF92" nocase ascii wide
                        $string7_SharpRDPThief_offensive_tool_keyword = "73B2C22B-C020-45B7-BF61-B48F49A2693F" nocase ascii wide
                        $string8_SharpRDPThief_offensive_tool_keyword = "bbfe2aee2092d981bd2822b8fde8db0ed264f0f86ed445d8987d99b505fd0ff5" nocase ascii wide
                        $string9_SharpRDPThief_offensive_tool_keyword = "FileMonitor has injected FileMonitorHook into process " nocase ascii wide
                        $string10_SharpRDPThief_offensive_tool_keyword = /Hook\sinstalled\sin\smstsc\.exe\,\sPID\s/ nocase ascii wide
                        $string11_SharpRDPThief_offensive_tool_keyword = "passthehashbrowns/SharpRDPThief" nocase ascii wide
                        $string12_SharpRDPThief_offensive_tool_keyword = "SharpRDPThief is a C# implementation of RDPThief" nocase ascii wide
                        $string13_SharpRDPThief_offensive_tool_keyword = /SharpRDPThief\.csproj/ nocase ascii wide
                        $string14_SharpRDPThief_offensive_tool_keyword = /SharpRDPThief\.exe/ nocase ascii wide

    condition:
        any of them
}