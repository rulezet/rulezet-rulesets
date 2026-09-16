rule OSCP_Cheatsheets
{
    meta:
        description = "Detection patterns for the tool 'OSCP-Cheatsheets' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSCP-Cheatsheets"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "kerberoasting" nocase ascii wide

    condition:
        any of them
}