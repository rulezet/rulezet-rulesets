rule rule_advanced_port_scanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_advanced_port_scanner_greyware_tool_keyword = /\/Advanced_Port_Scanner_.{0,100}\.exe/ nocase ascii wide
                        $string2_advanced_port_scanner_greyware_tool_keyword = /\/lansearch\.exe/ nocase ascii wide
                        $string3_advanced_port_scanner_greyware_tool_keyword = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
                        $string4_advanced_port_scanner_greyware_tool_keyword = /\\lansearch\.exe/ nocase ascii wide
                        $string5_advanced_port_scanner_greyware_tool_keyword = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
                        $string6_advanced_port_scanner_greyware_tool_keyword = ">Advanced Port Scanner Setup<" nocase ascii wide
                        $string7_advanced_port_scanner_greyware_tool_keyword = ">Advanced Port Scanner<" nocase ascii wide
                        $string8_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner\.exe/ nocase ascii wide
                        $string9_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner_console\.exe/ nocase ascii wide
                        $string10_advanced_port_scanner_greyware_tool_keyword = "d0c1662ce239e4d288048c0e3324ec52962f6ddda77da0cb7af9c1d9c2f1e2eb" nocase ascii wide
                        $string11_advanced_port_scanner_greyware_tool_keyword = /http\:\/\/www\.advanced\-port\-scanner\.com\/checkupdate\.php/ nocase ascii wide
                        $string12_advanced_port_scanner_greyware_tool_keyword = /lansearch\.exe\s/ nocase ascii wide
                        $string13_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_portable\.zip/ nocase ascii wide
                        $string14_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_setup\.exe/ nocase ascii wide
                        $string15_advanced_port_scanner_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide
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