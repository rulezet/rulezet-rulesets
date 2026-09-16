rule rule_SMBSR_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBSR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBSR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBSR_offensive_tool_keyword = /\ssmbsr\.db/ nocase ascii wide
                        $string2_SMBSR_offensive_tool_keyword = /\ssmbsr\.log/ nocase ascii wide
                        $string3_SMBSR_offensive_tool_keyword = /\s\-word\-list\-path\s.{0,1000}\s\-file\-extensions\s/ nocase ascii wide
                        $string4_SMBSR_offensive_tool_keyword = /\/smbsr\.db/ nocase ascii wide
                        $string5_SMBSR_offensive_tool_keyword = /\/SMBSR\.git/ nocase ascii wide
                        $string6_SMBSR_offensive_tool_keyword = /\/smbsr\.log/
                        $string7_SMBSR_offensive_tool_keyword = /smbsr\.py/ nocase ascii wide

    condition:
        any of them
}