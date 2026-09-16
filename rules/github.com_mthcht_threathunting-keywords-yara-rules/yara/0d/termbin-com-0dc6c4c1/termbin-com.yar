rule termbin_com
{
    meta:
        description = "Detection patterns for the tool 'termbin.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "termbin.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\snc\stermbin\.com\s/ nocase ascii wide
                        $string2 = /\snetcat\stermbin\.com\s/ nocase ascii wide
                        $string3 = /\stermbin\.com\s9999/ nocase ascii wide
                        $string4 = /curl\shttps\:\/\/termbin\.com\// nocase ascii wide
                        $string5 = /https\:\/\/termbin\.com\/test/ nocase ascii wide

    condition:
        any of them
}