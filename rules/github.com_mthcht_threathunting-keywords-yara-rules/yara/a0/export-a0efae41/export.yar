rule export
{
    meta:
        description = "Detection patterns for the tool 'export' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "export"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "export HISTFILE=/dev/null"
                        $string2 = "export HISTFILESIZE=0"
                        $string3 = "export HISTSIZE=0"

    condition:
        any of them
}