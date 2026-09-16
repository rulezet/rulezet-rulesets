rule rule_guerrillamail_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'guerrillamail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "guerrillamail"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_guerrillamail_greyware_tool_keyword = /http\:\/\/api\.guerrillamail\.com\/ajax\.php\?/ nocase ascii wide
                        $string2_guerrillamail_greyware_tool_keyword = /https\:\/\/www\.guerrillamail\.com\/compose/ nocase ascii wide
                        $string3_guerrillamail_greyware_tool_keyword = /https\:\/\/www\.guerrillamail\.com\/inbox/ nocase ascii wide

    condition:
        any of them
}