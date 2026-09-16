rule bcdedit
{
    meta:
        description = "Detection patterns for the tool 'bcdedit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcdedit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /bcdedit\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
                        $string2 = /bcdedit\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
                        $string3 = "bcdedit /set hypervisorlaunchtype off" nocase ascii wide
                        $string4 = /bcdedit.{0,1000}\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
                        $string5 = /bcdedit.{0,1000}\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide

    condition:
        any of them
}