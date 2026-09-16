rule rule_DumpLSASS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpLSASS_offensive_tool_keyword = /\/DumpLSASS\.git/ nocase ascii wide
                        $string2_DumpLSASS_offensive_tool_keyword = /\/MultiDump\.exe/ nocase ascii wide
                        $string3_DumpLSASS_offensive_tool_keyword = /\[\!\]\sDumping\sLSASS\sRequires\sElevated\sPriviledges\!/ nocase ascii wide
                        $string4_DumpLSASS_offensive_tool_keyword = /\[\!\]\sFailed\sto\sLocate\sLSASS\sDump\sFile\!/ nocase ascii wide
                        $string5_DumpLSASS_offensive_tool_keyword = /\[\+\]\sLSASS\sDump\sRead\:\s/ nocase ascii wide
                        $string6_DumpLSASS_offensive_tool_keyword = /\[i\]\sDumping\sLSASS\sUsing\s/ nocase ascii wide
                        $string7_DumpLSASS_offensive_tool_keyword = /\\a\\1\\s\\x64\\Release\\ProcDump64\.pdb/ nocase ascii wide
                        $string8_DumpLSASS_offensive_tool_keyword = /\\DumpLSASS\-main/ nocase ascii wide
                        $string9_DumpLSASS_offensive_tool_keyword = /\\MultiDump\.exe/ nocase ascii wide
                        $string10_DumpLSASS_offensive_tool_keyword = /\\Users\\Public\\lsass\.dmp/ nocase ascii wide
                        $string11_DumpLSASS_offensive_tool_keyword = /DumpLSASS\-main\.zip/ nocase ascii wide
                        $string12_DumpLSASS_offensive_tool_keyword = "elementalsouls/DumpLSASS" nocase ascii wide
                        $string13_DumpLSASS_offensive_tool_keyword = "f150333a3943f2c7398e0dd3f97a2cb3f1c1653a220785a977ba9a7ff692dab1" nocase ascii wide
                        $string14_DumpLSASS_offensive_tool_keyword = /Users\\\\Public\\\\lsass\.dmp/ nocase ascii wide
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