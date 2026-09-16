rule rule_GlllPowerloader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GlllPowerloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GlllPowerloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GlllPowerloader_offensive_tool_keyword = /\sGlllPowerLoader\.py/ nocase ascii wide
                        $string2_GlllPowerloader_offensive_tool_keyword = /\/APC_Injection\.cpp/ nocase ascii wide
                        $string3_GlllPowerloader_offensive_tool_keyword = /\/GlllPowerloader\.git/ nocase ascii wide
                        $string4_GlllPowerloader_offensive_tool_keyword = /\/GlllPowerLoader\.py/ nocase ascii wide
                        $string5_GlllPowerloader_offensive_tool_keyword = /\[\+\]\s\\u57fa\\u4e8esyswhispers\\u7684shellcode\\u52a0\\u8f7d\\u5668/ nocase ascii wide
                        $string6_GlllPowerloader_offensive_tool_keyword = /\[\+\]\s\\u68c0\\u6d4b\\u5230Stageless\spayload/ nocase ascii wide
                        $string7_GlllPowerloader_offensive_tool_keyword = /\[\+\]\sGenerated\ssuccessfully\!\sa\.dll/ nocase ascii wide
                        $string8_GlllPowerloader_offensive_tool_keyword = /\[\+\]\sGenerated\ssuccessfully\!\sa\.exe/ nocase ascii wide
                        $string9_GlllPowerloader_offensive_tool_keyword = /\[IO\.File\]\:\:ReadAllText\(.{0,100}stubps1tovbs\.ps1/ nocase ascii wide
                        $string10_GlllPowerloader_offensive_tool_keyword = /\\APC_Injection\.cpp/ nocase ascii wide
                        $string11_GlllPowerloader_offensive_tool_keyword = /\\GlllPowerLoader\.py/ nocase ascii wide
                        $string12_GlllPowerloader_offensive_tool_keyword = /\\GlllPowerLoader\-master/ nocase ascii wide
                        $string13_GlllPowerloader_offensive_tool_keyword = /\\Ps1ToVbs\.ps1/ nocase ascii wide
                        $string14_GlllPowerloader_offensive_tool_keyword = /\\wwwwwwwwwwwwntdll\.dll/ nocase ascii wide
                        $string15_GlllPowerloader_offensive_tool_keyword = "54d3497f0b4197a649280a6f464d71154d7ecbcc663ab00a3805e820900a7955" nocase ascii wide
                        $string16_GlllPowerloader_offensive_tool_keyword = "5643f39d347a5b36f195edcd9dbba33cc3417d76ad99892a029aefa96817b41a" nocase ascii wide
                        $string17_GlllPowerloader_offensive_tool_keyword = "67908b4e774d138792557c430f8ec4f48aa9094b0c639bd57e7f49aacc17788e" nocase ascii wide
                        $string18_GlllPowerloader_offensive_tool_keyword = "88391b7725953b6c37aa40ce11c2f80894ed4216f3972bef9c5738cc1771b143" nocase ascii wide
                        $string19_GlllPowerloader_offensive_tool_keyword = /del\sGreen\.vbs/ nocase ascii wide
                        $string20_GlllPowerloader_offensive_tool_keyword = /del\sPs1ToVbs\.ps1\\"/ nocase ascii wide
                        $string21_GlllPowerloader_offensive_tool_keyword = "e74146d0354389935edf4ef0dcfdf659572b1444db54f08cf0c7ade206fee3c5" nocase ascii wide
                        $string22_GlllPowerloader_offensive_tool_keyword = "INotGreen/GlllPowerloader" nocase ascii wide
                        $string23_GlllPowerloader_offensive_tool_keyword = "powershell_to_vbs,APC_Injection,RemoteThreadContext,RemoteThreadSuspended" nocase ascii wide
                        $string24_GlllPowerloader_offensive_tool_keyword = /powershell_to_vbs\.ps1/ nocase ascii wide
                        $string25_GlllPowerloader_offensive_tool_keyword = "Sleeping for 10 seconds to avoid in-memory AV scan" nocase ascii wide
                        $string26_GlllPowerloader_offensive_tool_keyword = /\-\-upload\-file.{0,100}transfer\.sh/ nocase ascii wide
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