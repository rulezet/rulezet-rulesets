rule SharpRDPThief
{
    meta:
        description = "Detection patterns for the tool 'SharpRDPThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDPThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sRDPHook\.dll/ nocase ascii wide
                        $string2 = /\/RDPHook\.dll/ nocase ascii wide
                        $string3 = /\/SharpRDPThief\.git/ nocase ascii wide
                        $string4 = /\\RDPHook\.dll/ nocase ascii wide
                        $string5 = /\\SharpRDPThief\\/ nocase ascii wide
                        $string6 = "20B3AA84-9CA7-43E5-B0CD-8DBA5091DF92" nocase ascii wide
                        $string7 = "73B2C22B-C020-45B7-BF61-B48F49A2693F" nocase ascii wide
                        $string8 = "bbfe2aee2092d981bd2822b8fde8db0ed264f0f86ed445d8987d99b505fd0ff5" nocase ascii wide
                        $string9 = "FileMonitor has injected FileMonitorHook into process " nocase ascii wide
                        $string10 = /Hook\sinstalled\sin\smstsc\.exe\,\sPID\s/ nocase ascii wide
                        $string11 = "passthehashbrowns/SharpRDPThief" nocase ascii wide
                        $string12 = "SharpRDPThief is a C# implementation of RDPThief" nocase ascii wide
                        $string13 = /SharpRDPThief\.csproj/ nocase ascii wide
                        $string14 = /SharpRDPThief\.exe/ nocase ascii wide

    condition:
        any of them
}