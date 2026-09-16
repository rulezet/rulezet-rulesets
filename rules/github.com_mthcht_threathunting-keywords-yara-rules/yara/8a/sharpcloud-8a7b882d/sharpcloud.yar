rule SharpCloud
{
    meta:
        description = "Detection patterns for the tool 'SharpCloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCloud"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpCloud\.git/ nocase ascii wide
                        $string2 = "chrismaddalena/SharpCloud" nocase ascii wide
                        $string3 = "execute_assembly SharpCloud" nocase ascii wide
                        $string4 = /sharpcloud\.cna/ nocase ascii wide
                        $string5 = /SharpCloud\.csproj/ nocase ascii wide
                        $string6 = /SharpCloud\.exe/ nocase ascii wide
                        $string7 = /SharpCloud\.sln/ nocase ascii wide
                        $string8 = "SharpCloud-master" nocase ascii wide

    condition:
        any of them
}