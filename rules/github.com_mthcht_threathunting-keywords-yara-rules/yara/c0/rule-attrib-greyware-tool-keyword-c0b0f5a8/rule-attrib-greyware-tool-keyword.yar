rule rule_attrib_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_attrib_greyware_tool_keyword = /\\attrib\.exe.{0,100}\s\+H\s/ nocase ascii wide
                        $string2_attrib_greyware_tool_keyword = /attrib\s.{0,100}\.rdp\s\-s\s\-h/ nocase ascii wide
                        $string3_attrib_greyware_tool_keyword = /attrib\s\+R\s\+S\s\+H\sC\:\\WINDOWS\\scvhost\.exe/ nocase ascii wide
                        $string4_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
                        $string5_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\users\\Public\\/ nocase ascii wide
                        $string6_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
                        $string7_attrib_greyware_tool_keyword = /attrib\sdesktop\.ini\s\+s\s\+h\s\+r/ nocase ascii wide
                        $string8_attrib_greyware_tool_keyword = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\explorer\.exe/ nocase ascii wide
                        $string9_attrib_greyware_tool_keyword = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\System32\\explorer\.exe/ nocase ascii wide
                        $string10_attrib_greyware_tool_keyword = "attrib -s -h %userprofile%" nocase ascii wide
                        $string11_attrib_greyware_tool_keyword = /attrib\s\-s\s\-h\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
                        $string12_attrib_greyware_tool_keyword = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
                        $string13_attrib_greyware_tool_keyword = /echo\sCLSID\=\{88C6C381\-2E85\-11D0\-94DE\-444553540000\}\s\>\>\sdesktop\.ini/ nocase ascii wide
                        $string14_attrib_greyware_tool_keyword = /echo\sIconResource\=\\\\.{0,100}\\.{0,100}\s\>\>\sdesktop\.ini/ nocase ascii wide
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