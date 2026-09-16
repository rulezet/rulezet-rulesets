rule rule_adobe_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adobe.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adobe.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adobe_com_greyware_tool_keyword = /https\:\/\/new\.express\.adobe\.com\/publishedV2\/urn\:aaid\:sc\:/ nocase ascii wide
                        $string2_adobe_com_greyware_tool_keyword = /https\:\/\/spark\.adobe\.com\/page\// nocase ascii wide

    condition:
        any of them
}