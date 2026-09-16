rule defender_control
{
    meta:
        description = "Detection patterns for the tool 'defender-control' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "defender-control"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Application\.Hacktool\.DisableDefender\.F/ nocase ascii wide
                        $string2 = "HackTool:Win32/DefenderControl" nocase ascii wide
                        $string3 = /PUA\.Win32\.DefenderControl/ nocase ascii wide
                        $string4 = /RiskWare\.DefenderControl/ nocase ascii wide
                        $string5 = /Win\.Tool\.Disabledefender/ nocase ascii wide

    condition:
        any of them
}