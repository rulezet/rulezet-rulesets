rule getent
{
    meta:
        description = "Detection patterns for the tool 'getent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "getent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /getent\spasswd\s\|\scut\s\-d\:\s\-f1/

    condition:
        any of them
}