rule rule_Tokenvator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tokenvator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tokenvator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Tokenvator_offensive_tool_keyword = /\sClone_Token\s\/Process\:.{0,100}\s\/Command\:/ nocase ascii wide
                        $string2_Tokenvator_offensive_tool_keyword = /\ssteal_token\s\/process\:.{0,100}\s\/command\:/ nocase ascii wide
                        $string3_Tokenvator_offensive_tool_keyword = " tokenvator " nocase ascii wide
                        $string4_Tokenvator_offensive_tool_keyword = /\/MonkeyWorks\.git/ nocase ascii wide
                        $string5_Tokenvator_offensive_tool_keyword = "/ServiceName:TokenDriver" nocase ascii wide
                        $string6_Tokenvator_offensive_tool_keyword = "/Tokenvator/" nocase ascii wide
                        $string7_Tokenvator_offensive_tool_keyword = /\\KernelTokens\.sys/ nocase ascii wide
                        $string8_Tokenvator_offensive_tool_keyword = /\\Tokenvator\\/ nocase ascii wide
                        $string9_Tokenvator_offensive_tool_keyword = "0xbadjuju/Tokenvator" nocase ascii wide
                        $string10_Tokenvator_offensive_tool_keyword = /Add_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
                        $string11_Tokenvator_offensive_tool_keyword = /BypassUAC\s.{0,100}\.exe/ nocase ascii wide
                        $string12_Tokenvator_offensive_tool_keyword = /Disable_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
                        $string13_Tokenvator_offensive_tool_keyword = /Enable_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
                        $string14_Tokenvator_offensive_tool_keyword = "Enumeration/DesktopACL" nocase ascii wide
                        $string15_Tokenvator_offensive_tool_keyword = /Enumeration\\DesktopAC/ nocase ascii wide
                        $string16_Tokenvator_offensive_tool_keyword = "List_Privileges /Process:powershell" nocase ascii wide
                        $string17_Tokenvator_offensive_tool_keyword = "Nuke_Privileges /Process:" nocase ascii wide
                        $string18_Tokenvator_offensive_tool_keyword = /Plugins\\AccessTokens\\TokenDriver/ nocase ascii wide
                        $string19_Tokenvator_offensive_tool_keyword = /Plugins\\AccessTokens\\TokenManipulation/ nocase ascii wide
                        $string20_Tokenvator_offensive_tool_keyword = /Plugins\\Execution\\PSExec/ nocase ascii wide
                        $string21_Tokenvator_offensive_tool_keyword = /Remove_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
                        $string22_Tokenvator_offensive_tool_keyword = "Steal_Pipe_Token /PipeName" nocase ascii wide
                        $string23_Tokenvator_offensive_tool_keyword = "Tokenvator" nocase ascii wide
                        $string24_Tokenvator_offensive_tool_keyword = /Tokenvator.{0,100}\.exe/ nocase ascii wide
                        $string25_Tokenvator_offensive_tool_keyword = /Tokenvator\.csproj/ nocase ascii wide
                        $string26_Tokenvator_offensive_tool_keyword = /Tokenvator\.exe/ nocase ascii wide
                        $string27_Tokenvator_offensive_tool_keyword = /Tokenvator\.git/ nocase ascii wide
                        $string28_Tokenvator_offensive_tool_keyword = /Tokenvator\.pdb/ nocase ascii wide
                        $string29_Tokenvator_offensive_tool_keyword = /Tokenvator\.Plugins/ nocase ascii wide
                        $string30_Tokenvator_offensive_tool_keyword = /Tokenvator\.Resources/ nocase ascii wide
                        $string31_Tokenvator_offensive_tool_keyword = /Tokenvator\.sln/ nocase ascii wide
                        $string32_Tokenvator_offensive_tool_keyword = "Tokenvator/MonkeyWorks" nocase ascii wide
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