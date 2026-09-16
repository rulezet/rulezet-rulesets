rule rule_scshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'scshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_scshell_offensive_tool_keyword = "/scshell"
                        $string2_scshell_offensive_tool_keyword = /payload\.csproj/ nocase ascii wide
                        $string3_scshell_offensive_tool_keyword = /payload\.sct\s/ nocase ascii wide

    condition:
        any of them
}