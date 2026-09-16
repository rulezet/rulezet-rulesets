rule rule_IIS_Raid_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IIS-Raid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IIS-Raid"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IIS_Raid_offensive_tool_keyword = /\siis_controller\.py/ nocase ascii wide
                        $string2_IIS_Raid_offensive_tool_keyword = " --url --password SIMPLEPASS" nocase ascii wide
                        $string3_IIS_Raid_offensive_tool_keyword = /\/iis_controller\.py/ nocase ascii wide
                        $string4_IIS_Raid_offensive_tool_keyword = /\/IIS\-Raid\.git/ nocase ascii wide
                        $string5_IIS_Raid_offensive_tool_keyword = /\[\+\]\sShellcode\sInjected\sSuccessfully/ nocase ascii wide
                        $string6_IIS_Raid_offensive_tool_keyword = /\\iis_controller\.py/ nocase ascii wide
                        $string7_IIS_Raid_offensive_tool_keyword = /\\Windows\\Temp\\creds\.db/ nocase ascii wide
                        $string8_IIS_Raid_offensive_tool_keyword = "0x09AL/IIS-Raid" nocase ascii wide
                        $string9_IIS_Raid_offensive_tool_keyword = "B5E39D15-9678-474A-9838-4C720243968B" nocase ascii wide
                        $string10_IIS_Raid_offensive_tool_keyword = /IIS\-Backdoor\./ nocase ascii wide
                        $string11_IIS_Raid_offensive_tool_keyword = "IIS-Raid-master" nocase ascii wide
                        $string12_IIS_Raid_offensive_tool_keyword = /Inject\sshellcode\son\sthe\sserver\.\\\\nUsage\:\sinject/ nocase ascii wide

    condition:
        any of them
}