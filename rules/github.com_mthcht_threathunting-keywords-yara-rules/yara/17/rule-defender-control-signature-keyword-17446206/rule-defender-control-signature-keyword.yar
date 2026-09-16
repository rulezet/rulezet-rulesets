rule rule_defender_control_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'defender-control' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "defender-control"
        rule_category = "signature_keyword"

    strings:
                        $string1_defender_control_signature_keyword = /Application\.Hacktool\.DisableDefender\.F/ nocase ascii wide
                        $string2_defender_control_signature_keyword = "HackTool:Win32/DefenderControl" nocase ascii wide
                        $string3_defender_control_signature_keyword = /PUA\.Win32\.DefenderControl/ nocase ascii wide
                        $string4_defender_control_signature_keyword = /RiskWare\.DefenderControl/ nocase ascii wide
                        $string5_defender_control_signature_keyword = /Win\.Tool\.Disabledefender/ nocase ascii wide

    condition:
        any of them
}