rule PPLKiller
{
    meta:
        description = "Detection patterns for the tool 'PPLKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\/disableLSAProtection/ nocase ascii wide
                        $string2 = /\/PPLKiller\.git/ nocase ascii wide
                        $string3 = "/PPLKiller/" nocase ascii wide
                        $string4 = /\\PPLKiller/ nocase ascii wide
                        $string5 = /\\Temp\\RTCore64\.sys/ nocase ascii wide
                        $string6 = /PPLKiller\.exe/ nocase ascii wide
                        $string7 = /PPLKiller\.sln/ nocase ascii wide
                        $string8 = /PPLKiller\.vcxproj/ nocase ascii wide
                        $string9 = "PPLKiller-master" nocase ascii wide
                        $string10 = /processPIDByName.{0,1000}lsass\.exe/ nocase ascii wide

    condition:
        any of them
}