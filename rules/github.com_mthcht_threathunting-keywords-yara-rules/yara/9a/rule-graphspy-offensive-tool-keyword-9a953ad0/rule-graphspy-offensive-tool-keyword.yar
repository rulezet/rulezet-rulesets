rule rule_GraphSpy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GraphSpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphSpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GraphSpy_offensive_tool_keyword = /\sGraphSpy\.py/ nocase ascii wide
                        $string2_GraphSpy_offensive_tool_keyword = /\/\.gspy\/databases\//
                        $string3_GraphSpy_offensive_tool_keyword = /\/\.local\/bin\/graphspy/
                        $string4_GraphSpy_offensive_tool_keyword = /\/GraphSpy\.git/ nocase ascii wide
                        $string5_GraphSpy_offensive_tool_keyword = /\/GraphSpy\.py/ nocase ascii wide
                        $string6_GraphSpy_offensive_tool_keyword = /\/opt\/gspy_log\.txt/
                        $string7_GraphSpy_offensive_tool_keyword = /\/pypi\.org\/project\/GraphSpy/ nocase ascii wide
                        $string8_GraphSpy_offensive_tool_keyword = /\\GraphSpy\.py/ nocase ascii wide
                        $string9_GraphSpy_offensive_tool_keyword = /\]\sStarting\sGraphSpy\.\sOpen\sin\syour\sbrowser\sby\sgoing\sto\sthe\surl\sdisplayed\sbelow\./ nocase ascii wide
                        $string10_GraphSpy_offensive_tool_keyword = "828411d980e653c3fa63dd031839e52ae1800b4f29f3b03f7acad492811dce2b" nocase ascii wide
                        $string11_GraphSpy_offensive_tool_keyword = /app\.config\[\'graph_spy_db_folder\'\]/ nocase ascii wide
                        $string12_GraphSpy_offensive_tool_keyword = /app\.config\[\'graph_spy_db_path\'\]/ nocase ascii wide
                        $string13_GraphSpy_offensive_tool_keyword = "f0037d99bc3119fc613d304af20599e8c791b1c99208d5d452a01738777f7b49" nocase ascii wide
                        $string14_GraphSpy_offensive_tool_keyword = "graphspy -i " nocase ascii wide
                        $string15_GraphSpy_offensive_tool_keyword = /GraphSpy\.GraphSpy\:main/ nocase ascii wide
                        $string16_GraphSpy_offensive_tool_keyword = /GraphSpy\-master\.zip/ nocase ascii wide
                        $string17_GraphSpy_offensive_tool_keyword = "pipx install graphspy" nocase ascii wide
                        $string18_GraphSpy_offensive_tool_keyword = "pipx upgrade graphspy" nocase ascii wide
                        $string19_GraphSpy_offensive_tool_keyword = "RedByte1337/GraphSpy" nocase ascii wide
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