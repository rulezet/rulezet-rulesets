rule sdelete
{
    meta:
        description = "Detection patterns for the tool 'sdelete' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sdelete"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/sdelete\.exe/ nocase ascii wide
                        $string2 = /\/SDelete\.zip/ nocase ascii wide
                        $string3 = /\/sdelete64\.exe/ nocase ascii wide
                        $string4 = /\/sdelete64a\.exe/ nocase ascii wide
                        $string5 = /\\sdelete\.exe/ nocase ascii wide
                        $string6 = /\\SDelete\.zip/ nocase ascii wide
                        $string7 = /\\sdelete64\.exe/ nocase ascii wide
                        $string8 = /\\sdelete64a\.exe/ nocase ascii wide
                        $string9 = /\\Software\\Sysinternals\\Sdelete/ nocase ascii wide
                        $string10 = /\>sdelete\.exe\</ nocase ascii wide
                        $string11 = ">sysinternals sdelete<" nocase ascii wide

    condition:
        any of them
}