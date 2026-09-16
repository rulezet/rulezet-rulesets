rule rule_RustHound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RustHound_offensive_tool_keyword = " --adcs --old-bloodhound " nocase ascii wide
                        $string2_RustHound_offensive_tool_keyword = /\s\-c\sDCOnly\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-o\s\/tmp/ nocase ascii wide
                        $string3_RustHound_offensive_tool_keyword = /\srusthound\.exe/ nocase ascii wide
                        $string4_RustHound_offensive_tool_keyword = /\/rusthound\.exe/ nocase ascii wide
                        $string5_RustHound_offensive_tool_keyword = /\/RustHound\.git/ nocase ascii wide
                        $string6_RustHound_offensive_tool_keyword = /\\rusthound\.exe/ nocase ascii wide
                        $string7_RustHound_offensive_tool_keyword = "--collectionmethod DCOnly" nocase ascii wide
                        $string8_RustHound_offensive_tool_keyword = "OPENCYBER-FR/RustHound" nocase ascii wide
                        $string9_RustHound_offensive_tool_keyword = /rusthound\s.{0,1000}\-\-domain/ nocase ascii wide
                        $string10_RustHound_offensive_tool_keyword = /rusthound\s.{0,1000}\-\-ldapfqdn\s/ nocase ascii wide
                        $string11_RustHound_offensive_tool_keyword = /rusthound\s.{0,1000}\-ldaps\s/ nocase ascii wide
                        $string12_RustHound_offensive_tool_keyword = "rusthound -c " nocase ascii wide
                        $string13_RustHound_offensive_tool_keyword = "rusthound -d " nocase ascii wide
                        $string14_RustHound_offensive_tool_keyword = "rusthound rusthound linux"
                        $string15_RustHound_offensive_tool_keyword = "rusthound rusthound windows" nocase ascii wide
                        $string16_RustHound_offensive_tool_keyword = /rusthound.{0,1000}\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
                        $string17_RustHound_offensive_tool_keyword = /rusthound\.exe/ nocase ascii wide
                        $string18_RustHound_offensive_tool_keyword = "RustHound-main" nocase ascii wide
                        $string19_RustHound_offensive_tool_keyword = /sharphound\.exe/ nocase ascii wide
                        $string20_RustHound_offensive_tool_keyword = "usr/src/rusthound rusthound " nocase ascii wide

    condition:
        any of them
}