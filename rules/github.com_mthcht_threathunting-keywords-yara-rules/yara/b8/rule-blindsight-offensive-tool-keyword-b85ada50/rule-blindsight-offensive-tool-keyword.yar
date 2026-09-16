rule rule_blindsight_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'blindsight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blindsight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_blindsight_offensive_tool_keyword = " - Dump LSASS memory bypassing countermeasures" nocase ascii wide
                        $string2_blindsight_offensive_tool_keyword = /\s29ABE9Hy\.log/ nocase ascii wide
                        $string3_blindsight_offensive_tool_keyword = /\/blindsight\.exe/ nocase ascii wide
                        $string4_blindsight_offensive_tool_keyword = /\/blindsight\.git/ nocase ascii wide
                        $string5_blindsight_offensive_tool_keyword = /\[\+\]\sFound\s\{LSASS\}\spid\:\s\{pid\}/ nocase ascii wide
                        $string6_blindsight_offensive_tool_keyword = /\[\+\]\sSuccessfully\sopened\s\{LSASS\}\shandle/ nocase ascii wide
                        $string7_blindsight_offensive_tool_keyword = /\\blindsight\.exe/ nocase ascii wide
                        $string8_blindsight_offensive_tool_keyword = /\\lsass\.dmp/ nocase ascii wide
                        $string9_blindsight_offensive_tool_keyword = "0xdea/blindsight" nocase ascii wide
                        $string10_blindsight_offensive_tool_keyword = "461356f9bd764b57b3b9a1457aa60494ae73a7935133f5b6122edcb286b7ef0a" nocase ascii wide

    condition:
        any of them
}