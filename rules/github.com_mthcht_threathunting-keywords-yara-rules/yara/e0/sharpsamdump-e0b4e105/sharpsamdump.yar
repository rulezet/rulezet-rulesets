rule SharpSAMDump
{
    meta:
        description = "Detection patterns for the tool 'SharpSAMDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSAMDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpSAMDump\.git/ nocase ascii wide
                        $string2 = /\\SharpSAMDump\-main/ nocase ascii wide
                        $string3 = ">SharpSAMDump<" nocase ascii wide
                        $string4 = "158c0b33376d319848cffd69f20dc6e2dc93aa66ed71dffd6f0ee3803da70dd2" nocase ascii wide
                        $string5 = "4FEAB888-F514-4F2E-A4F7-5989A86A69DE" nocase ascii wide
                        $string6 = "f97334c71892acdc50380141f0c6144363b7a55a1fe5adf01543b2adbd2d7e44" nocase ascii wide
                        $string7 = "jojonas/SharpSAMDump" nocase ascii wide
                        $string8 = /SharpSAMDump\.exe/ nocase ascii wide
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