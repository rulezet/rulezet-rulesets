rule rule_aweray_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'aweray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aweray"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_aweray_greyware_tool_keyword = /\.aweray\.net/ nocase ascii wide
                        $string2_aweray_greyware_tool_keyword = /\/Aweray_Remote_.{0,100}\.exe/ nocase ascii wide
                        $string3_aweray_greyware_tool_keyword = /\/Aweray_Remote_.{0,100}\.zip/ nocase ascii wide
                        $string4_aweray_greyware_tool_keyword = /\\Aweray\sRemote\.lnk/ nocase ascii wide
                        $string5_aweray_greyware_tool_keyword = /\\Aweray_Remote_.{0,100}\.exe/ nocase ascii wide
                        $string6_aweray_greyware_tool_keyword = /\\Aweray_Remote_.{0,100}\.zip/ nocase ascii wide
                        $string7_aweray_greyware_tool_keyword = /\\AweSun\.exe/ nocase ascii wide
                        $string8_aweray_greyware_tool_keyword = /\\Program\sFiles\\Aweray/ nocase ascii wide
                        $string9_aweray_greyware_tool_keyword = /\\Software\\AweSun\\SunLogin\\SunloginClient/ nocase ascii wide
                        $string10_aweray_greyware_tool_keyword = ">AweRay Limited<" nocase ascii wide
                        $string11_aweray_greyware_tool_keyword = /\>AweRay\sPte\.\sLtd\.\</ nocase ascii wide
                        $string12_aweray_greyware_tool_keyword = /\>AweSun\.exe\</ nocase ascii wide
                        $string13_aweray_greyware_tool_keyword = ">AweSun<" nocase ascii wide
                        $string14_aweray_greyware_tool_keyword = /asapi\.aweray\.net/ nocase ascii wide
                        $string15_aweray_greyware_tool_keyword = /as\-tk\.aweray\.com/ nocase ascii wide
                        $string16_aweray_greyware_tool_keyword = /as\-tk\.aweray\.com\/track/ nocase ascii wide
                        $string17_aweray_greyware_tool_keyword = /Aweray_Remote\.exe/ nocase ascii wide
                        $string18_aweray_greyware_tool_keyword = /awerayimg\.com/ nocase ascii wide
                        $string19_aweray_greyware_tool_keyword = /client\-api\.aweray\.com/ nocase ascii wide
                        $string20_aweray_greyware_tool_keyword = /https\:\/\/sun\.aweray\.com\/.{0,100}\/download/ nocase ascii wide
                        $string21_aweray_greyware_tool_keyword = /install\.bat\sAweSun/ nocase ascii wide
                        $string22_aweray_greyware_tool_keyword = /netsh\s\sadvfirewall\sfirewall\s.{0,100}\srule\sname\=\\"AweSun/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}