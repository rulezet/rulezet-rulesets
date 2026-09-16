rule blindsight
{
    meta:
        description = "Detection patterns for the tool 'blindsight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blindsight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " - Dump LSASS memory bypassing countermeasures" nocase ascii wide
                        $string2 = /\s29ABE9Hy\.log/ nocase ascii wide
                        $string3 = /\/blindsight\.exe/ nocase ascii wide
                        $string4 = /\/blindsight\.git/ nocase ascii wide
                        $string5 = /\[\+\]\sFound\s\{LSASS\}\spid\:\s\{pid\}/ nocase ascii wide
                        $string6 = /\[\+\]\sSuccessfully\sopened\s\{LSASS\}\shandle/ nocase ascii wide
                        $string7 = /\\blindsight\.exe/ nocase ascii wide
                        $string8 = /\\lsass\.dmp/ nocase ascii wide
                        $string9 = "0xdea/blindsight" nocase ascii wide
                        $string10 = "461356f9bd764b57b3b9a1457aa60494ae73a7935133f5b6122edcb286b7ef0a" nocase ascii wide

    condition:
        any of them
}