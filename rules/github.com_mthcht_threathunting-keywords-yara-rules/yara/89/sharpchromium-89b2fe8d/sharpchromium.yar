rule SharpChromium
{
    meta:
        description = "Detection patterns for the tool 'SharpChromium' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpChromium"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpChromium\.git/ nocase ascii wide
                        $string2 = /\\SharpChromium\\/ nocase ascii wide
                        $string3 = "djhohnstein/SharpChromium" nocase ascii wide
                        $string4 = "F1653F20-D47D-4F29-8C55-3C835542AF5F" nocase ascii wide
                        $string5 = /SharpChromium\.csproj/ nocase ascii wide
                        $string6 = /SharpChromium\.exe/ nocase ascii wide
                        $string7 = /SharpChromium\.sln/ nocase ascii wide
                        $string8 = "SharpChromium-master" nocase ascii wide

    condition:
        any of them
}