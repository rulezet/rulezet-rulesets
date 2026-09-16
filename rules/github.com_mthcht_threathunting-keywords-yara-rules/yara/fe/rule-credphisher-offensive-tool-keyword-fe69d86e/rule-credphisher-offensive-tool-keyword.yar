rule rule_CredPhisher_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CredPhisher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredPhisher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CredPhisher_offensive_tool_keyword = "/CredPhisher/" nocase ascii wide
                        $string2_CredPhisher_offensive_tool_keyword = /CredPhisher\.csproj/ nocase ascii wide
                        $string3_CredPhisher_offensive_tool_keyword = /CredPhisher\.exe/ nocase ascii wide
                        $string4_CredPhisher_offensive_tool_keyword = "namespace CredPhisher" nocase ascii wide

    condition:
        any of them
}