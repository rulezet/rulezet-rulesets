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
                        $string2_VirtualBox_greyware_tool_keyword = /\ssharedfolder\sadd\s.{0,100}\s\-hostpath\sc\:\\\s\-automount/ nocase ascii wide
                        $string3_VirtualBox_greyware_tool_keyword = /\\VboxHeadless\.exe\\"\s\-startvm\s.{0,100}\s\-v\soff/ nocase ascii wide
                        $string4_VirtualBox_greyware_tool_keyword = /\<SharedFolder\sname\=\\".{0,100}\\"\shostPath\=\\"C\:\\\\"\swritable\=\\"true\\"\/\>/ nocase ascii wide
                        $string5_VirtualBox_greyware_tool_keyword = "setextradata global GUI/SuppressMessages \"all\"" nocase ascii wide
                        $string6_VirtualBox_greyware_tool_keyword = "setextradata global GUI/SuppressMessages all" nocase ascii wide
                        $string7_VirtualBox_greyware_tool_keyword = /start\s\/min\s\\"C\:\\Program\sFiles\\Oracle\\VirtualBox\\VBoxManage\.exe\\"\sstartvm\s.{0,100}\s\-type\sheadless/ nocase ascii wide
                        $string8_VirtualBox_greyware_tool_keyword = /VboxHeadless\.exe\s\-startvm\s.{0,100}\s\-v\soff/ nocase ascii wide
                        $string9_VirtualBox_greyware_tool_keyword = /VBoxManage\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
                        $string10_VirtualBox_greyware_tool_keyword = /VBoxManage.{0,100}setextradata\sglobal\sGUI\/SuppressMessages\s/ nocase ascii wide
                        $string11_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
                        $string12_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\sstartvm\s.{0,100}\s\-v\soff/ nocase ascii wide
                        $string13_VirtualBox_greyware_tool_keyword = /VBoxManage\.exe\\"\sstartvm\s.{0,100}\s\-\-type\sheadless/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}