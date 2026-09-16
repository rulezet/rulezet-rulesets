rule rule_canarytokens_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'canarytokens.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canarytokens.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_canarytokens_com_greyware_tool_keyword = /http\:\/\/canarytokens\.com\/.{0,1000}\// nocase ascii wide

    condition:
        any of them
}