rule CredPhisher
{
    meta:
        description = "Detection patterns for the tool 'CredPhisher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredPhisher"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/CredPhisher/" nocase ascii wide
                        $string2 = /CredPhisher\.csproj/ nocase ascii wide
                        $string3 = /CredPhisher\.exe/ nocase ascii wide
                        $string4 = "namespace CredPhisher" nocase ascii wide

    condition:
        any of them
}