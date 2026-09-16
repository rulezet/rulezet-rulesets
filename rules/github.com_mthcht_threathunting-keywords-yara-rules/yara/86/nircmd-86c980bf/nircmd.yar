rule nircmd
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\snircmd\.exe/ nocase ascii wide
                        $string2 = /\snircmdc\.exe/ nocase ascii wide
                        $string3 = /\/nircmd\.exe/ nocase ascii wide
                        $string4 = /\/nircmd\.zip/ nocase ascii wide
                        $string5 = /\/nircmdc\.exe/ nocase ascii wide
                        $string6 = /\/nircmd\-x64\.zip/ nocase ascii wide
                        $string7 = /\\nircmd\.exe/ nocase ascii wide
                        $string8 = /\\nircmd\.zip/ nocase ascii wide
                        $string9 = /\\nircmdc\.exe/ nocase ascii wide
                        $string10 = /\\nircmd\-x64\.zip/ nocase ascii wide
                        $string11 = /nircmd\.exe\s/ nocase ascii wide
                        $string12 = /nircmdc\.exe\s/ nocase ascii wide

    condition:
        any of them
}