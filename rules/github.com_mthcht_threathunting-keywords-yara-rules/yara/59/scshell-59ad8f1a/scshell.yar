rule scshell
{
    meta:
        description = "Detection patterns for the tool 'scshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/scshell"
                        $string2 = /payload\.csproj/ nocase ascii wide
                        $string3 = /payload\.sct\s/ nocase ascii wide

    condition:
        any of them
}