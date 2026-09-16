rule samba
{
    meta:
        description = "Detection patterns for the tool 'samba' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samba"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "net rpc group members 'Domain Users' -W " nocase ascii wide

    condition:
        any of them
}