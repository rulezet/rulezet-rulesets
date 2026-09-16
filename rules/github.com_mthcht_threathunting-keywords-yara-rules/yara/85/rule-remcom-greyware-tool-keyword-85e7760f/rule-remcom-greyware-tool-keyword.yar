rule rule_RemCom_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RemCom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemCom"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_RemCom_greyware_tool_keyword = /\s\\\\\\\\localhost\s\/user\:Username\s\/pwd\:Password\s\s\\\\"C\:\\\\InstallMe\.bat/ nocase ascii wide
                        $string2_RemCom_greyware_tool_keyword = /\sRemCom\.exe/ nocase ascii wide
                        $string3_RemCom_greyware_tool_keyword = /\sRemComSvc\.exe/ nocase ascii wide
                        $string4_RemCom_greyware_tool_keyword = /\sRemComSvc\.h/ nocase ascii wide
                        $string5_RemCom_greyware_tool_keyword = /\.\\RemComSvc\\/ nocase ascii wide
                        $string6_RemCom_greyware_tool_keyword = /\/RemCom\.exe/ nocase ascii wide
                        $string7_RemCom_greyware_tool_keyword = /\/RemCom\.git/ nocase ascii wide
                        $string8_RemCom_greyware_tool_keyword = /\/RemComSvc\.exe/ nocase ascii wide
                        $string9_RemCom_greyware_tool_keyword = /\[\stalha\.tariq\@gmail\.com\s\]/ nocase ascii wide
                        $string10_RemCom_greyware_tool_keyword = /\\RemCom\.cpp/ nocase ascii wide
                        $string11_RemCom_greyware_tool_keyword = /\\RemCom\.exe/ nocase ascii wide
                        $string12_RemCom_greyware_tool_keyword = /\\RemCom\.pdb/ nocase ascii wide
                        $string13_RemCom_greyware_tool_keyword = /\\RemCom\.vcxproj/ nocase ascii wide
                        $string14_RemCom_greyware_tool_keyword = /\\RemCom\-master\\/ nocase ascii wide
                        $string15_RemCom_greyware_tool_keyword = /\\RemComSvc\.exe/ nocase ascii wide
                        $string16_RemCom_greyware_tool_keyword = /\\RemComSvc\\/ nocase ascii wide
                        $string17_RemCom_greyware_tool_keyword = /\\Remote\sCommand\sExecutor\.sln/ nocase ascii wide
                        $string18_RemCom_greyware_tool_keyword = "0d8f28ea01d3866ad7ee4abbdc5bdfd83d41702dcf029584ef30cb0055be8538" nocase ascii wide
                        $string19_RemCom_greyware_tool_keyword = "29548EB7-5E44-21F9-5C82-15DDDC80449A" nocase ascii wide
                        $string20_RemCom_greyware_tool_keyword = "8CC59FFA-00E0-0AEA-59E8-E780672C3CB3" nocase ascii wide
                        $string21_RemCom_greyware_tool_keyword = "C7038612-8183-67A7-8A9C-1379C2674156" nocase ascii wide
                        $string22_RemCom_greyware_tool_keyword = "define RemComSVCEXE" nocase ascii wide
                        $string23_RemCom_greyware_tool_keyword = "eee20962a1056f525bbe1c99c656794511697e510221522e7d62efd943457190" nocase ascii wide
                        $string24_RemCom_greyware_tool_keyword = "kavika13/RemCom" nocase ascii wide
                        $string25_RemCom_greyware_tool_keyword = "RemCom - Win32 Debug" nocase ascii wide
                        $string26_RemCom_greyware_tool_keyword = "RemCom - Win32 Release" nocase ascii wide
                        $string27_RemCom_greyware_tool_keyword = "RemComSvc - Win32 Debug" nocase ascii wide
                        $string28_RemCom_greyware_tool_keyword = "RemComSvc - Win32 Release" nocase ascii wide
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