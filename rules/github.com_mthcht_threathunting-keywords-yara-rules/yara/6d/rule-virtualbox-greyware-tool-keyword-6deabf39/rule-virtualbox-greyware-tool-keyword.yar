rule rule_VirtualBox_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VirtualBox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirtualBox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_VirtualBox_greyware_tool_keyword = /\shostPath\=\\"c\:\\\\"\swritable\=\\"true\\"\sautoMount\=\\"true\\"/ nocase ascii wide
                        $string2_VirtualBox_greyware_tool_keyword = /\ssharedfolder\sadd\s.{0,1000}\s\-hostpath\sc\:\\\s\-automount/ nocase ascii wide
                        $string3_VirtualBox_greyware_tool_keyword = /\\VboxHeadless\.exe\\"\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string4_VirtualBox_greyware_tool_keyword = /\<SharedFolder\sname\=\\".{0,1000}\\"\shostPath\=\\"C\:\\\\"\swritable\=\\"true\\"\/\>/ nocase ascii wide
                        $string5_VirtualBox_greyware_tool_keyword = "setextradata global GUI/SuppressMessages \"all\"" nocase ascii wide
                        $string6_VirtualBox_greyware_tool_keyword = "setextradata global GUI/SuppressMessages all" nocase ascii wide
                        $string7_VirtualBox_greyware_tool_keyword = /start\s\/min\s\\"C\:\\Program\sFiles\\Oracle\\VirtualBox\\VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-type\sheadless/ nocase ascii wide
                        $string8_VirtualBox_greyware_tool_keyword = /VboxHeadless\.exe\s\-startvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string9_VirtualBox_greyware_tool_keyword = /VBoxManage\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
                        $string10_VirtualBox_greyware_tool_keyword = /VBoxManage.{0,1000}setextradata\sglobal\sGUI\/SuppressMessages\s/ nocase ascii wide
                        $string11_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide
                        $string12_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\sstartvm\s.{0,1000}\s\-v\soff/ nocase ascii wide
                        $string13_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\\"\sstartvm\s.{0,1000}\s\-\-type\sheadless/ nocase ascii wide

    condition:
        any of them
}