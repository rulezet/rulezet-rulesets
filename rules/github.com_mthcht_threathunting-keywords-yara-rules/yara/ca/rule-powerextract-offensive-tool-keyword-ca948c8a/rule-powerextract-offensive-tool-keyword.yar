rule rule_powerextract_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'powerextract' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerextract"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_powerextract_offensive_tool_keyword = /\s\-PathToDMP\s.{0,1000}\.dmp/ nocase ascii wide
                        $string2_powerextract_offensive_tool_keyword = /\/PowerExtract\.git/ nocase ascii wide
                        $string3_powerextract_offensive_tool_keyword = /\/PowerExtract\.git/ nocase ascii wide
                        $string4_powerextract_offensive_tool_keyword = "Get-KIWI_KERBEROS_LOGON_SESSION" nocase ascii wide
                        $string5_powerextract_offensive_tool_keyword = "Invoke-PowerExtract" nocase ascii wide
                        $string6_powerextract_offensive_tool_keyword = /PowerExtract\-main\.zip/ nocase ascii wide
                        $string7_powerextract_offensive_tool_keyword = "powerseb/PowerExtract" nocase ascii wide
                        $string8_powerextract_offensive_tool_keyword = "powerseb/PowerExtract" nocase ascii wide

    condition:
        any of them
}