rule Eternalblue_Doublepulsar_Metasploit
{
    meta:
        description = "Detection patterns for the tool 'Eternalblue-Doublepulsar-Metasploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eternalblue-Doublepulsar-Metasploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Eternalblue-Doublepulsar" nocase ascii wide

    condition:
        any of them
}