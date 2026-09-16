rule commando_vm
{
    meta:
        description = "Detection patterns for the tool 'commando-vm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commando-vm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.win10\.config\.fireeye/ nocase ascii wide
                        $string2 = /\.win7\.config\.fireeye/ nocase ascii wide
                        $string3 = "/commando-vm" nocase ascii wide
                        $string4 = /choco\sinstall\s.{0,1000}\scommon\.fireeye/ nocase ascii wide
                        $string5 = /cmd\.cat\/chattr/ nocase ascii wide
                        $string6 = /commandovm\..{0,1000}\.installer\.fireeye/ nocase ascii wide
                        $string7 = "commando-vm-master" nocase ascii wide
                        $string8 = /\-ExecutionPolicy\sBypass\s\-File\sWin10\.ps1\s/ nocase ascii wide
                        $string9 = /\-ExecutionPolicy\sBypass\s\-File\sWin11\.ps1\s/ nocase ascii wide
                        $string10 = /fireeye.{0,1000}commando/ nocase ascii wide
                        $string11 = /https\:\/\/www\.myget\.org\/F\/fireeye\/api\/v2/ nocase ascii wide
                        $string12 = /Unblock\-File\s\.\\install\.ps1/ nocase ascii wide

    condition:
        any of them
}