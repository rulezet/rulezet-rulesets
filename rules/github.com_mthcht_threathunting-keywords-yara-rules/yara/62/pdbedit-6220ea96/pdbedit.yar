rule pdbedit
{
    meta:
        description = "Detection patterns for the tool 'pdbedit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pdbedit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "pdbedit -L -v" nocase ascii wide
                        $string2 = "pdbedit -L -w" nocase ascii wide

    condition:
        any of them
}