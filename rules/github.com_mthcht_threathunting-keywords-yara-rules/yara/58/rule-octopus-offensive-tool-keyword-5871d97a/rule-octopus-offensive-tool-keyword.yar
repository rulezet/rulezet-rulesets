rule rule_octopus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'octopus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "octopus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_octopus_offensive_tool_keyword = " deploy_cobalt_beacon" nocase ascii wide
                        $string2_octopus_offensive_tool_keyword = /\soctopus\.py/ nocase ascii wide
                        $string3_octopus_offensive_tool_keyword = /\.\/.{0,100}octopus\.py/
                        $string4_octopus_offensive_tool_keyword = /\/agent\.ps1\.oct/ nocase ascii wide
                        $string5_octopus_offensive_tool_keyword = /\/octopus\.asm/ nocase ascii wide
                        $string6_octopus_offensive_tool_keyword = /\/Octopus\.git/ nocase ascii wide
                        $string7_octopus_offensive_tool_keyword = /\/octopusx64\.asm/ nocase ascii wide
                        $string8_octopus_offensive_tool_keyword = /\/weblistener\.py/ nocase ascii wide
                        $string9_octopus_offensive_tool_keyword = /ASBBypass\.ps1/ nocase ascii wide
                        $string10_octopus_offensive_tool_keyword = "generate_hta operation1" nocase ascii wide
                        $string11_octopus_offensive_tool_keyword = "generate_powershell operation1" nocase ascii wide
                        $string12_octopus_offensive_tool_keyword = "generate_spoofed_args_exe" nocase ascii wide
                        $string13_octopus_offensive_tool_keyword = /generate_unmanaged_exe\soperation1\s.{0,100}\.exe/ nocase ascii wide
                        $string14_octopus_offensive_tool_keyword = "generate_x64_shellcode" nocase ascii wide
                        $string15_octopus_offensive_tool_keyword = "generate_x86_shellcode" nocase ascii wide
                        $string16_octopus_offensive_tool_keyword = /ILBypass\.ps1/ nocase ascii wide
                        $string17_octopus_offensive_tool_keyword = /listen_http\s0\.0\.0\.0\s8080\s.{0,100}\.php\soperation1/ nocase ascii wide
                        $string18_octopus_offensive_tool_keyword = "mhaskar/Octopus" nocase ascii wide
                        $string19_octopus_offensive_tool_keyword = /octopus\.py\s/ nocase ascii wide
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