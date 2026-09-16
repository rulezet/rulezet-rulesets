rule rule_blackcat_ransomware_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'blackcat ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackcat ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_blackcat_ransomware_offensive_tool_keyword = " --drop-drag-and-drop-target" nocase ascii wide
                        $string2_blackcat_ransomware_offensive_tool_keyword = " --no-vm-kill" nocase ascii wide
                        $string3_blackcat_ransomware_offensive_tool_keyword = " --no-vm-snapshot-kill" nocase ascii wide
                        $string4_blackcat_ransomware_offensive_tool_keyword = /bcdedit\.exe\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
                        $string5_blackcat_ransomware_offensive_tool_keyword = /iisreset\.exe\s\/stop/ nocase ascii wide
                        $string6_blackcat_ransomware_offensive_tool_keyword = /wmic\.exe.{0,1000}\sShadowcopy\sDelete/ nocase ascii wide

    condition:
        any of them
}