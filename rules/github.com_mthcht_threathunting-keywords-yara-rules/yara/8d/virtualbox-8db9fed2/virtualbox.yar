rule VirtualBox
{
    meta:
        description = "Detection patterns for the tool 'VirtualBox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirtualBox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\shostPath\=\\"c\:\\\\"\swritable\=\\"true\\"\sautoMount\=\\"true\\"/ nocase ascii wide
                        $string2 = /\ssharedfolder\sadd\s.{0,1000}\s\-hostpath\sc\:\\\s\-automount/ nocase ascii wide
                        $string3 = /\\VboxHeadless\.exe\\"\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string4 = /\<SharedFolder\sname\=\\".{0,1000}\\"\shostPath\=\\"C\:\\\\"\swritable\=\\"true\\"\/\>/ nocase ascii wide
                        $string5 = "setextradata global GUI/SuppressMessages \"all\"" nocase ascii wide
                        $string6 = "setextradata global GUI/SuppressMessages all" nocase ascii wide
                        $string7 = /start\s\/min\s\\"C\:\\Program\sFiles\\Oracle\\VirtualBox\\VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-type\sheadless/ nocase ascii wide
                        $string8 = /VboxHeadless\.exe\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string9 = /VBoxManage\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
                        $string10 = /VBoxManage.{0,1000}setextradata\sglobal\sGUI\/SuppressMessages\s/ nocase ascii wide
                        $string11 = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
                        $string12 = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string13 = /VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide

    condition:
        any of them
}