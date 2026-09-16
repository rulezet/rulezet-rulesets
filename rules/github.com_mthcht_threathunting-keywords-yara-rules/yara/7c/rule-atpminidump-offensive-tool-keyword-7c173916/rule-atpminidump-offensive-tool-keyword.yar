rule rule_ATPMiniDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ATPMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ATPMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ATPMiniDump_offensive_tool_keyword = /\/ATPMiniDump\.git/ nocase ascii wide
                        $string2_ATPMiniDump_offensive_tool_keyword = /\[\!\]\sFailed\sto\screate\sminidump/ nocase ascii wide
                        $string3_ATPMiniDump_offensive_tool_keyword = /\\dumpert\.dmp/ nocase ascii wide
                        $string4_ATPMiniDump_offensive_tool_keyword = "0538b3096657777e14c5ac6296037b936df7fb375d32199b0ae1b7fe33b3d63b" nocase ascii wide
                        $string5_ATPMiniDump_offensive_tool_keyword = "53a8f4b6cd47f980a97be192fdbf70c028065c7bfdf2e461927c7561eafbea6b" nocase ascii wide
                        $string6_ATPMiniDump_offensive_tool_keyword = "920B8C5B-0DC5-4BD7-B6BB-D14B39BFC9FE" nocase ascii wide
                        $string7_ATPMiniDump_offensive_tool_keyword = "ATPMiniDump" nocase ascii wide
                        $string8_ATPMiniDump_offensive_tool_keyword = "b4rtik/ATPMiniDump" nocase ascii wide
                        $string9_ATPMiniDump_offensive_tool_keyword = "By b4rtik & uf0" nocase ascii wide
                        $string10_ATPMiniDump_offensive_tool_keyword = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase ascii wide
                        $string11_ATPMiniDump_offensive_tool_keyword = "Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot" nocase ascii wide
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