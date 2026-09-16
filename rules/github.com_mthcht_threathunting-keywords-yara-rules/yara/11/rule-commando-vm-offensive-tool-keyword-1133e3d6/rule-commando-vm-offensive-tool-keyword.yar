rule rule_commando_vm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'commando-vm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commando-vm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_commando_vm_offensive_tool_keyword = /\.win10\.config\.fireeye/ nocase ascii wide
                        $string2_commando_vm_offensive_tool_keyword = /\.win7\.config\.fireeye/ nocase ascii wide
                        $string3_commando_vm_offensive_tool_keyword = "/commando-vm" nocase ascii wide
                        $string4_commando_vm_offensive_tool_keyword = /choco\sinstall\s.{0,1000}\scommon\.fireeye/ nocase ascii wide
                        $string5_commando_vm_offensive_tool_keyword = /cmd\.cat\/chattr/ nocase ascii wide
                        $string6_commando_vm_offensive_tool_keyword = /commandovm\..{0,1000}\.installer\.fireeye/ nocase ascii wide
                        $string7_commando_vm_offensive_tool_keyword = "commando-vm-master" nocase ascii wide
                        $string8_commando_vm_offensive_tool_keyword = /\-ExecutionPolicy\sBypass\s\-File\sWin10\.ps1\s/ nocase ascii wide
                        $string9_commando_vm_offensive_tool_keyword = /\-ExecutionPolicy\sBypass\s\-File\sWin11\.ps1\s/ nocase ascii wide
                        $string10_commando_vm_offensive_tool_keyword = /fireeye.{0,1000}commando/ nocase ascii wide
                        $string11_commando_vm_offensive_tool_keyword = /https\:\/\/www\.myget\.org\/F\/fireeye\/api\/v2/ nocase ascii wide
                        $string12_commando_vm_offensive_tool_keyword = /Unblock\-File\s\.\\install\.ps1/ nocase ascii wide

    condition:
        any of them
}