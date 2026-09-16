rule etwunhook
{
    meta:
        description = "Detection patterns for the tool 'etwunhook' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "etwunhook"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\setwunhook\.cpp/ nocase ascii wide
                        $string2 = /\setwunhook\.exe/ nocase ascii wide
                        $string3 = /\/etwunhook\.cpp/ nocase ascii wide
                        $string4 = /\/etwunhook\.exe/ nocase ascii wide
                        $string5 = /\/etwunhook\.git/ nocase ascii wide
                        $string6 = /\\etwunhook\.cpp/ nocase ascii wide
                        $string7 = /\\etwunhook\.exe/ nocase ascii wide
                        $string8 = "Meowmycks/etwunhook" nocase ascii wide

    condition:
        any of them
}