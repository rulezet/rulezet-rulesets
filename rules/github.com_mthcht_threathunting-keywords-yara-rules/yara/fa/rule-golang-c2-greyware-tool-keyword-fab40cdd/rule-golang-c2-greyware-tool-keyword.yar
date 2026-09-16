rule rule_golang_c2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'golang_c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "golang_c2"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_golang_c2_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:8000\/gate\.html/ nocase ascii wide

    condition:
        any of them
}