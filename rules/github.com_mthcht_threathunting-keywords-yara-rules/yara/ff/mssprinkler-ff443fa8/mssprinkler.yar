rule MSSprinkler
{
    meta:
        description = "Detection patterns for the tool 'MSSprinkler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSSprinkler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\smssprinkler\.ps1/ nocase ascii wide
                        $string2 = /\s\-user\suserlist\.txt\s\-pass\spasswordlist\.txt\s/ nocase ascii wide
                        $string3 = /\/MSSprinkler\.git/ nocase ascii wide
                        $string4 = /\/mssprinkler\.ps1/ nocase ascii wide
                        $string5 = /\\mssprinkler\.ps1/ nocase ascii wide
                        $string6 = "c299346734b17df1a8dc47d97145c756938307fbd249837ff4dc697befd2961b" nocase ascii wide
                        $string7 = "Invoke-MSSprinkler" nocase ascii wide
                        $string8 = "TheresAFewConors/MSSprinkler" nocase ascii wide

    condition:
        any of them
}