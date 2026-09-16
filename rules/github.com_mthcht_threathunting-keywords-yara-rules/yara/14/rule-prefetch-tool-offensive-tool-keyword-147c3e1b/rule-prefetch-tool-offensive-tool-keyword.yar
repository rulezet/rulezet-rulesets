rule rule_prefetch_tool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'prefetch-tool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prefetch-tool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_prefetch_tool_offensive_tool_keyword = /\/prefetch\-tool\.git/ nocase ascii wide
                        $string2_prefetch_tool_offensive_tool_keyword = /\\prefetch_leak\.h/ nocase ascii wide
                        $string3_prefetch_tool_offensive_tool_keyword = /\\prefetch_tool\.sln/ nocase ascii wide
                        $string4_prefetch_tool_offensive_tool_keyword = /\\prefetch_tool\.vcxproj/ nocase ascii wide
                        $string5_prefetch_tool_offensive_tool_keyword = "82ac960f25131540ae230b2bac0f003ffc8edc8a05382d8831ff8e8ebf30996d" nocase ascii wide
                        $string6_prefetch_tool_offensive_tool_keyword = "8aba74be7acef3c84cef0163411298aa994872347a4ac84cc0a0d19ddf0eb65c" nocase ascii wide
                        $string7_prefetch_tool_offensive_tool_keyword = "A46C9A13-145E-42C0-8CA6-CC920BF1D9F1" nocase ascii wide
                        $string8_prefetch_tool_offensive_tool_keyword = "exploits-forsale/prefetch-tool" nocase ascii wide
                        $string9_prefetch_tool_offensive_tool_keyword = /include\s\\"prefetch_leak\.h\\"/ nocase ascii wide
                        $string10_prefetch_tool_offensive_tool_keyword = /lallousz\-x86\@yahoo\.com/ nocase ascii wide
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