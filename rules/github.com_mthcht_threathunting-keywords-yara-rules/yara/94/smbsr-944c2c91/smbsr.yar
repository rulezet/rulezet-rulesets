rule SMBSR
{
    meta:
        description = "Detection patterns for the tool 'SMBSR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBSR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssmbsr\.db/ nocase ascii wide
                        $string2 = /\ssmbsr\.log/ nocase ascii wide
                        $string3 = /\s\-word\-list\-path\s.{0,1000}\s\-file\-extensions\s/ nocase ascii wide
                        $string4 = /\/smbsr\.db/ nocase ascii wide
                        $string5 = /\/SMBSR\.git/ nocase ascii wide
                        $string6 = /\/smbsr\.log/
                        $string7 = /smbsr\.py/ nocase ascii wide

    condition:
        any of them
}