rule rule_SMBTrap_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBTrap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBTrap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBTrap_offensive_tool_keyword = /\squickcrack\.py/ nocase ascii wide
                        $string2_SMBTrap_offensive_tool_keyword = /\sredirecttosmb\.py/ nocase ascii wide
                        $string3_SMBTrap_offensive_tool_keyword = /\ssmbtrap2\.py/ nocase ascii wide
                        $string4_SMBTrap_offensive_tool_keyword = /\ssmbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string5_SMBTrap_offensive_tool_keyword = /\/quickcrack\.py/ nocase ascii wide
                        $string6_SMBTrap_offensive_tool_keyword = /\/redirecttosmb\.py/ nocase ascii wide
                        $string7_SMBTrap_offensive_tool_keyword = /\/SMBTrap\.git/ nocase ascii wide
                        $string8_SMBTrap_offensive_tool_keyword = /\/smbtrap2\.py/ nocase ascii wide
                        $string9_SMBTrap_offensive_tool_keyword = /\/smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string10_SMBTrap_offensive_tool_keyword = /\\quickcrack\.py/ nocase ascii wide
                        $string11_SMBTrap_offensive_tool_keyword = /\\redirecttosmb\.py/ nocase ascii wide
                        $string12_SMBTrap_offensive_tool_keyword = /\\smbtrap2\.py/ nocase ascii wide
                        $string13_SMBTrap_offensive_tool_keyword = /\\smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string14_SMBTrap_offensive_tool_keyword = "06f43329147155af22520cda36202f9af0bd46b5e30b3d3f202d2a463aa2729d" nocase ascii wide
                        $string15_SMBTrap_offensive_tool_keyword = "432bb0868bd1152ce689dda88d274bb05671174c5c892c7db0575e50abcadf4c" nocase ascii wide
                        $string16_SMBTrap_offensive_tool_keyword = "c9def37771dabf11171830fdd27b3b751955f40c577fae3f9691188ed3f90b08" nocase ascii wide
                        $string17_SMBTrap_offensive_tool_keyword = "cylance/SMBTrap" nocase ascii wide
                        $string18_SMBTrap_offensive_tool_keyword = "de25283c258cc462a919df98ff3033b6f433cf0ab4d92e95a650099839c45e63" nocase ascii wide
                        $string19_SMBTrap_offensive_tool_keyword = "import try_to_crack_hash" nocase ascii wide
                        $string20_SMBTrap_offensive_tool_keyword = /redirecttosmb\.py\s/ nocase ascii wide
                        $string21_SMBTrap_offensive_tool_keyword = "smbtrap-mitmproxy-inline" nocase ascii wide
                        $string22_SMBTrap_offensive_tool_keyword = /try_to_crack_hash\(/ nocase ascii wide
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