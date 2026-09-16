rule pwdump
{
    meta:
        description = "Detection patterns for the tool 'pwdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "4747b86b7a8d2ba61f377e2526d6f2764cb8146be5dd8d6ad42af745dd705c8b" nocase ascii wide
                        $string2 = "PWDump" nocase ascii wide
                        $string3 = /PWDump\./ nocase ascii wide

    condition:
        any of them
}