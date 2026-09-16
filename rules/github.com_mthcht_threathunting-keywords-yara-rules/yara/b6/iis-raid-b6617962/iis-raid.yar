rule IIS_Raid
{
    meta:
        description = "Detection patterns for the tool 'IIS-Raid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IIS-Raid"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\siis_controller\.py/ nocase ascii wide
                        $string2 = " --url --password SIMPLEPASS" nocase ascii wide
                        $string3 = /\/iis_controller\.py/ nocase ascii wide
                        $string4 = /\/IIS\-Raid\.git/ nocase ascii wide
                        $string5 = /\[\+\]\sShellcode\sInjected\sSuccessfully/ nocase ascii wide
                        $string6 = /\\iis_controller\.py/ nocase ascii wide
                        $string7 = /\\Windows\\Temp\\creds\.db/ nocase ascii wide
                        $string8 = "0x09AL/IIS-Raid" nocase ascii wide
                        $string9 = "B5E39D15-9678-474A-9838-4C720243968B" nocase ascii wide
                        $string10 = /IIS\-Backdoor\./ nocase ascii wide
                        $string11 = "IIS-Raid-master" nocase ascii wide
                        $string12 = /Inject\sshellcode\son\sthe\sserver\.\\\\nUsage\:\sinject/ nocase ascii wide

    condition:
        any of them
}