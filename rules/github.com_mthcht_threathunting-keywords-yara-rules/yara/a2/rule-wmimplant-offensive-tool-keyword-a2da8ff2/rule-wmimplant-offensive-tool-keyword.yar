rule rule_WMImplant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMImplant_offensive_tool_keyword = /\s\-Remote_Posh\s\-Location\s.{0,100}\.ps1\s\-Function\sInvoke\-.{0,100}\s\-ComputerName\s/ nocase ascii wide
                        $string2_WMImplant_offensive_tool_keyword = "Edit-FileWMI" nocase ascii wide
                        $string3_WMImplant_offensive_tool_keyword = "Find-FileWMImplant" nocase ascii wide
                        $string4_WMImplant_offensive_tool_keyword = "Find-VacantComputer" nocase ascii wide
                        $string5_WMImplant_offensive_tool_keyword = "Get-FileContentsWMImplant" nocase ascii wide
                        $string6_WMImplant_offensive_tool_keyword = "Get-WMIEventLogins" nocase ascii wide
                        $string7_WMImplant_offensive_tool_keyword = "Invoke-FileTransferWMImplant" nocase ascii wide
                        $string8_WMImplant_offensive_tool_keyword = "Invoke-LSWMImplant" nocase ascii wide
                        $string9_WMImplant_offensive_tool_keyword = "Invoke-PowerOptionsWMI" nocase ascii wide
                        $string10_WMImplant_offensive_tool_keyword = "Invoke-ProcessPunisher" nocase ascii wide
                        $string11_WMImplant_offensive_tool_keyword = "Invoke-ProcSpawn -Command " nocase ascii wide
                        $string12_WMImplant_offensive_tool_keyword = "Invoke-ProcSpawn" nocase ascii wide
                        $string13_WMImplant_offensive_tool_keyword = "Invoke-RemoteScriptWithOutput" nocase ascii wide
                        $string14_WMImplant_offensive_tool_keyword = "Invoke-WMImplant" nocase ascii wide
                        $string15_WMImplant_offensive_tool_keyword = "Invoke-WMIObfuscatedPSCommand" nocase ascii wide
                        $string16_WMImplant_offensive_tool_keyword = /powershell\.exe\s\-command\s.{0,100}Enable\-PSRemoting\s\-Force.{0,100}\s\-ComputerName\s/ nocase ascii wide
                        $string17_WMImplant_offensive_tool_keyword = "Show-WMImplantMainMenu" nocase ascii wide
                        $string18_WMImplant_offensive_tool_keyword = "WMImplant" nocase ascii wide
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