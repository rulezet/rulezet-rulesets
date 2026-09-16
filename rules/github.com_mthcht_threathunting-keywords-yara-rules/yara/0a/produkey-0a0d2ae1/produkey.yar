rule produkey
{
    meta:
        description = "Detection patterns for the tool 'produkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "produkey"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/ProduKey\.exe/ nocase ascii wide
                        $string2 = /\\ProduKey\.exe/ nocase ascii wide
                        $string3 = /produkey\.zip/ nocase ascii wide
                        $string4 = /produkey_setup\.exe/ nocase ascii wide
                        $string5 = /produkey\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}