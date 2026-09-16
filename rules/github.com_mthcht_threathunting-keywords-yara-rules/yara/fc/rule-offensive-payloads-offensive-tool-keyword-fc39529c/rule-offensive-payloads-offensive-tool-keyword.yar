rule rule_Offensive_Payloads_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Offensive_Payloads_offensive_tool_keyword = "Cross-Site-Scripting-XSS-Payloads" nocase ascii wide
                        $string2_Offensive_Payloads_offensive_tool_keyword = /Directory\-Traversal\-Payloads\./ nocase ascii wide
                        $string3_Offensive_Payloads_offensive_tool_keyword = /File\-Extensions\-Wordlist\.txt/ nocase ascii wide
                        $string4_Offensive_Payloads_offensive_tool_keyword = /Html\-Injection\-Payloads\./ nocase ascii wide
                        $string5_Offensive_Payloads_offensive_tool_keyword = /Html\-Injection\-Read\-File\-Payloads\./ nocase ascii wide
                        $string6_Offensive_Payloads_offensive_tool_keyword = /OS\-Command\-Injection\-Unix\-Payloads\./ nocase ascii wide
                        $string7_Offensive_Payloads_offensive_tool_keyword = /OS\-Command\-Injection\-Windows\-Payloads\./ nocase ascii wide
                        $string8_Offensive_Payloads_offensive_tool_keyword = /PHP\-Code\-injection\./ nocase ascii wide
                        $string9_Offensive_Payloads_offensive_tool_keyword = /PHP\-Code\-Injections\-Payloads\./ nocase ascii wide
                        $string10_Offensive_Payloads_offensive_tool_keyword = /Server\-Side\-Request\-Forgery\-Payloads\./ nocase ascii wide
                        $string11_Offensive_Payloads_offensive_tool_keyword = /SQL\-Injection\-Auth\-Bypass\-Payloads\./ nocase ascii wide
                        $string12_Offensive_Payloads_offensive_tool_keyword = /SQL\-Injection\-Payloads\./ nocase ascii wide
                        $string13_Offensive_Payloads_offensive_tool_keyword = /XML\-External\-Entity\-\(XXE\)\-Payloads/ nocase ascii wide
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