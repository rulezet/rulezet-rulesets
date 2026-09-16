rule rule_spoolsploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spoolsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoolsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spoolsploit_offensive_tool_keyword = " -a nightmare" nocase ascii wide
                        $string2_spoolsploit_offensive_tool_keyword = " -a spoolsample" nocase ascii wide
                        $string3_spoolsploit_offensive_tool_keyword = /\sevil\.corp\s/ nocase ascii wide
                        $string4_spoolsploit_offensive_tool_keyword = " spoolsploit " nocase ascii wide
                        $string5_spoolsploit_offensive_tool_keyword = /\/smbserver\/smb_server\.py/ nocase ascii wide
                        $string6_spoolsploit_offensive_tool_keyword = "/ssploit/" nocase ascii wide
                        $string7_spoolsploit_offensive_tool_keyword = "--attack nightmare" nocase ascii wide
                        $string8_spoolsploit_offensive_tool_keyword = "--attack spoolsample" nocase ascii wide
                        $string9_spoolsploit_offensive_tool_keyword = "BeetleChunks/SpoolSploit" nocase ascii wide
                        $string10_spoolsploit_offensive_tool_keyword = /impacket\./ nocase ascii wide
                        $string11_spoolsploit_offensive_tool_keyword = /malicious\.dll/ nocase ascii wide
                        $string12_spoolsploit_offensive_tool_keyword = /PrintNightmare\./ nocase ascii wide
                        $string13_spoolsploit_offensive_tool_keyword = /spool_sploit\.py/ nocase ascii wide
                        $string14_spoolsploit_offensive_tool_keyword = "SpoolSploit/" nocase ascii wide
                        $string15_spoolsploit_offensive_tool_keyword = "spoolsploit:latest" nocase ascii wide

    condition:
        any of them
}