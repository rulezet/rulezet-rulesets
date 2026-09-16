rule guerrillamail
{
    meta:
        description = "Detection patterns for the tool 'guerrillamail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "guerrillamail"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /http\:\/\/api\.guerrillamail\.com\/ajax\.php\?/ nocase ascii wide
                        $string2 = /https\:\/\/www\.guerrillamail\.com\/compose/ nocase ascii wide
                        $string3 = /https\:\/\/www\.guerrillamail\.com\/inbox/ nocase ascii wide

    condition:
        any of them
}