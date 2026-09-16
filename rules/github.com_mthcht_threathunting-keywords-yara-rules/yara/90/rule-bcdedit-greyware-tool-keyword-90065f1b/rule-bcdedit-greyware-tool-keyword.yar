rule rule_bcdedit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bcdedit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcdedit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bcdedit_greyware_tool_keyword = /bcdedit\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
                        $string2_bcdedit_greyware_tool_keyword = /bcdedit\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
                        $string3_bcdedit_greyware_tool_keyword = "bcdedit /set hypervisorlaunchtype off" nocase ascii wide
                        $string4_bcdedit_greyware_tool_keyword = /bcdedit.{0,1000}\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
                        $string5_bcdedit_greyware_tool_keyword = /bcdedit.{0,1000}\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide

    condition:
        any of them
}