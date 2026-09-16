rule spoolsploit
{
    meta:
        description = "Detection patterns for the tool 'spoolsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoolsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -a nightmare" nocase ascii wide
                        $string2 = " -a spoolsample" nocase ascii wide
                        $string3 = /\sevil\.corp\s/ nocase ascii wide
                        $string4 = " spoolsploit " nocase ascii wide
                        $string5 = /\/smbserver\/smb_server\.py/ nocase ascii wide
                        $string6 = "/ssploit/" nocase ascii wide
                        $string7 = "--attack nightmare" nocase ascii wide
                        $string8 = "--attack spoolsample" nocase ascii wide
                        $string9 = "BeetleChunks/SpoolSploit" nocase ascii wide
                        $string10 = /impacket\./ nocase ascii wide
                        $string11 = /malicious\.dll/ nocase ascii wide
                        $string12 = /PrintNightmare\./ nocase ascii wide
                        $string13 = /spool_sploit\.py/ nocase ascii wide
                        $string14 = "SpoolSploit/" nocase ascii wide
                        $string15 = "spoolsploit:latest" nocase ascii wide

    condition:
        any of them
}