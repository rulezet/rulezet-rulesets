rule rule_chimera_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chimera' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chimera"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chimera_offensive_tool_keyword = /\schimera\.sh/ nocase ascii wide
                        $string2_chimera_offensive_tool_keyword = /\s\-f\s.{0,100}\.ps1\s\-l\s3\s\-o\s.{0,100}\.ps1\s\-v\s\-t\spowershell.{0,100}reverse/ nocase ascii wide
                        $string3_chimera_offensive_tool_keyword = /\s\-f\sshells\/generic1\.ps1\s/ nocase ascii wide
                        $string4_chimera_offensive_tool_keyword = /\s\-s\s.{0,100}ascii.{0,100}\s\-b\s.{0,100}reverse.{0,100}invoke\-expression/ nocase ascii wide
                        $string5_chimera_offensive_tool_keyword = /\/Chimera\.git/ nocase ascii wide
                        $string6_chimera_offensive_tool_keyword = /\/chimera\.sh/ nocase ascii wide
                        $string7_chimera_offensive_tool_keyword = "/opt/chimera"
                        $string8_chimera_offensive_tool_keyword = /\/tmp\/chimera\.ps1/
                        $string9_chimera_offensive_tool_keyword = /\/tmp\/payload\.ps1/
                        $string10_chimera_offensive_tool_keyword = /\/tmp\/vt\-post\-.{0,100}\.txt/
                        $string11_chimera_offensive_tool_keyword = /\/tmp\/vt\-results\-.{0,100}\.txt/
                        $string12_chimera_offensive_tool_keyword = /Add\-RegBackdoor\.ps1/ nocase ascii wide
                        $string13_chimera_offensive_tool_keyword = /Chimera\-master\.zip/ nocase ascii wide
                        $string14_chimera_offensive_tool_keyword = /Get\-WLAN\-Keys\.ps1/ nocase ascii wide
                        $string15_chimera_offensive_tool_keyword = "Invoke-PortScan" nocase ascii wide
                        $string16_chimera_offensive_tool_keyword = "Invoke-PoshRatHttp" nocase ascii wide
                        $string17_chimera_offensive_tool_keyword = /Invoke\-PowerShellIcmp\.ps1/ nocase ascii wide
                        $string18_chimera_offensive_tool_keyword = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
                        $string19_chimera_offensive_tool_keyword = /Invoke\-PowerShellTcpOneLine\.ps1/ nocase ascii wide
                        $string20_chimera_offensive_tool_keyword = /Invoke\-PowerShellUdp\.ps1/ nocase ascii wide
                        $string21_chimera_offensive_tool_keyword = /Invoke\-PowerShellUdpOneLine\.ps1/ nocase ascii wide
                        $string22_chimera_offensive_tool_keyword = /null\-byte\.com\/bypass\-amsi/ nocase ascii wide
                        $string23_chimera_offensive_tool_keyword = /powershell_reverse_shell\.ps1/ nocase ascii wide
                        $string24_chimera_offensive_tool_keyword = "tokyoneon/Chimera" nocase ascii wide
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