rule blackcat_ransomware
{
    meta:
        description = "Detection patterns for the tool 'blackcat ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackcat ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --drop-drag-and-drop-target" nocase ascii wide
                        $string2 = " --no-vm-kill" nocase ascii wide
                        $string3 = " --no-vm-snapshot-kill" nocase ascii wide
                        $string4 = /bcdedit\.exe\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
                        $string5 = /iisreset\.exe\s\/stop/ nocase ascii wide
                        $string6 = /wmic\.exe.{0,1000}\sShadowcopy\sDelete/ nocase ascii wide

    condition:
        any of them
}