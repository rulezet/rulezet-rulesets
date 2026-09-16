rule advanced_ip_scanner
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.exe\s\/s\:ip_ranges\.txt\s\/f\:scan_results\.txt/ nocase ascii wide
                        $string2 = /\\Advanced\sIP\sScanner\.lnk/ nocase ascii wide
                        $string3 = /\\advanced_ip_scanner/ nocase ascii wide
                        $string4 = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
                        $string5 = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
                        $string6 = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
                        $string7 = /\\Start\sMenu\\Programs\\Advanced\sIP\sScanner\sv2/ nocase ascii wide
                        $string8 = ">Advanced IP Scanner Setup<" nocase ascii wide
                        $string9 = ">Advanced IP Scanner<" nocase ascii wide
                        $string10 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string11 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
                        $string12 = "Advanced IP Scanner" nocase ascii wide
                        $string13 = /Advanced_IP_Scanner.{0,100}\.exe/ nocase ascii wide
                        $string14 = /advanced_ip_scanner_console\.exe/ nocase ascii wide
                        $string15 = /https\:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,100}\.exe/ nocase ascii wide
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