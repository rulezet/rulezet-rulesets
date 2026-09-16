rule RustHound
{
    meta:
        description = "Detection patterns for the tool 'RustHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --adcs --old-bloodhound " nocase ascii wide
                        $string2 = /\s\-c\sDCOnly\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-o\s\/tmp/ nocase ascii wide
                        $string3 = /\srusthound\.exe/ nocase ascii wide
                        $string4 = /\/rusthound\.exe/ nocase ascii wide
                        $string5 = /\/RustHound\.git/ nocase ascii wide
                        $string6 = /\\rusthound\.exe/ nocase ascii wide
                        $string7 = "--collectionmethod DCOnly" nocase ascii wide
                        $string8 = "OPENCYBER-FR/RustHound" nocase ascii wide
                        $string9 = /rusthound\s.{0,1000}\-\-domain/ nocase ascii wide
                        $string10 = /rusthound\s.{0,1000}\-\-ldapfqdn\s/ nocase ascii wide
                        $string11 = /rusthound\s.{0,1000}\-ldaps\s/ nocase ascii wide
                        $string12 = "rusthound -c " nocase ascii wide
                        $string13 = "rusthound -d " nocase ascii wide
                        $string14 = "rusthound rusthound linux"
                        $string15 = "rusthound rusthound windows" nocase ascii wide
                        $string16 = /rusthound.{0,1000}\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
                        $string17 = /rusthound\.exe/ nocase ascii wide
                        $string18 = "RustHound-main" nocase ascii wide
                        $string19 = /sharphound\.exe/ nocase ascii wide
                        $string20 = "usr/src/rusthound rusthound " nocase ascii wide

    condition:
        any of them
}