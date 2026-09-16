rule Browser_C2
{
    meta:
        description = "Detection patterns for the tool 'Browser-C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-C2"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /http\:\/\/127\.0\.0\.1\:8081/ nocase ascii wide

    condition:
        any of them
}