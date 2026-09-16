rule rule_HRShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HRShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HRShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HRShell_offensive_tool_keyword = /\sclient\.py\s\-s\shttp.{0,100}\:5000\s\-\-cert\s\/.{0,100}\.pem/ nocase ascii wide
                        $string2_HRShell_offensive_tool_keyword = /\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,100}pem\s\-\-key\s\/.{0,100}\.pem/ nocase ascii wide
                        $string3_HRShell_offensive_tool_keyword = /\/HRShell\.git/ nocase ascii wide
                        $string4_HRShell_offensive_tool_keyword = "/HRShell/" nocase ascii wide
                        $string5_HRShell_offensive_tool_keyword = "/meterpreter/reverse_tcp" nocase ascii wide
                        $string6_HRShell_offensive_tool_keyword = /\/shellcodes\/utils\.py/ nocase ascii wide
                        $string7_HRShell_offensive_tool_keyword = "chrispetrou/HRShell" nocase ascii wide
                        $string8_HRShell_offensive_tool_keyword = "exploit -j -z" nocase ascii wide
                        $string9_HRShell_offensive_tool_keyword = "from shellcodes import " nocase ascii wide
                        $string10_HRShell_offensive_tool_keyword = "history_cmd" nocase ascii wide
                        $string11_HRShell_offensive_tool_keyword = /HRShell.{0,100}client\.py/ nocase ascii wide
                        $string12_HRShell_offensive_tool_keyword = /HRShell.{0,100}server\.py/ nocase ascii wide
                        $string13_HRShell_offensive_tool_keyword = "inject shellcode" nocase ascii wide
                        $string14_HRShell_offensive_tool_keyword = "set shellcode " nocase ascii wide
                        $string15_HRShell_offensive_tool_keyword = "set_shellcode" nocase ascii wide
                        $string16_HRShell_offensive_tool_keyword = /shellcode1\s\+\=\sb/ nocase ascii wide
                        $string17_HRShell_offensive_tool_keyword = "set shellcode " nocase ascii wide
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