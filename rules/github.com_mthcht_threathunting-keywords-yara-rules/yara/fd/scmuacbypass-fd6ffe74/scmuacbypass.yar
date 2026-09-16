rule SCMUACBypass
{
    meta:
        description = "Detection patterns for the tool 'SCMUACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCMUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sscmuacbypass\.cpp/ nocase ascii wide
                        $string2 = /\sscmuacbypass\.exe/ nocase ascii wide
                        $string3 = /\/scmuacbypass\.cpp/ nocase ascii wide
                        $string4 = /\/SCMUACBypass\.exe/ nocase ascii wide
                        $string5 = /\/scmuacbypass\.exe/ nocase ascii wide
                        $string6 = /\/SCMUACBypass\.git/ nocase ascii wide
                        $string7 = "/SCMUACBypass/" nocase ascii wide
                        $string8 = /\\scmuacbypass\.cpp/ nocase ascii wide
                        $string9 = /\\scmuacbypass\.exe/ nocase ascii wide
                        $string10 = /\\SCMUACBypass\.exe/ nocase ascii wide
                        $string11 = /\\SCMUACBypass\\/ nocase ascii wide
                        $string12 = /UACBypassedService\.exe/ nocase ascii wide

    condition:
        any of them
}