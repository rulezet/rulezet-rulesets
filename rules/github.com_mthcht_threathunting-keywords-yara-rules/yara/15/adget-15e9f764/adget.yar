rule adget
{
    meta:
        description = "Detection patterns for the tool 'adget' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adget"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/ADGet\.exe/ nocase ascii wide
                        $string2 = /\\ADGet\.exe/ nocase ascii wide

    condition:
        any of them
}