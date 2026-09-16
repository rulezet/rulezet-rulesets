rule rule_CelestialSpark_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CelestialSpark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CelestialSpark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CelestialSpark_offensive_tool_keyword = "// A: the Meterpreter stage is a large shellcode " nocase ascii wide
                        $string2_CelestialSpark_offensive_tool_keyword = /\/\/\sDefine\sIP\sAdress\sof\syour\sC2\sStager\s\(\!\)/ nocase ascii wide
                        $string3_CelestialSpark_offensive_tool_keyword = /\/CelestialSpark\.git/ nocase ascii wide
                        $string4_CelestialSpark_offensive_tool_keyword = /\[\!\]\sFailed\sto\sload\sshellcode\sinto\smemory/ nocase ascii wide
                        $string5_CelestialSpark_offensive_tool_keyword = /\\asm_CelestialSpark\.x64\.o/ nocase ascii wide
                        $string6_CelestialSpark_offensive_tool_keyword = /\\loader\.x64\.exe/ nocase ascii wide
                        $string7_CelestialSpark_offensive_tool_keyword = "482002c785db1a3432ec214464a19042a3f36a21e5617a9901a0eae9f04451f1" nocase ascii wide
                        $string8_CelestialSpark_offensive_tool_keyword = "b8c9caeda6743d224835019b8bdc0105ad54f9a804a33e7e51acb605a8e8bc25" nocase ascii wide
                        $string9_CelestialSpark_offensive_tool_keyword = "Karkas66/CelestialSpark" nocase ascii wide
                        $string10_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,100}\\"Stardust\sSocket\sFailed\\"/ nocase ascii wide
                        $string11_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,100}\\"Stardust\sSocket\sInitialization\\"/ nocase ascii wide
                        $string12_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,100}\\"We\sare\sall\smade\sof\sStardust\!\\"/ nocase ascii wide
                        $string13_CelestialSpark_offensive_tool_keyword = "'S', 'T', 'A', 'R', 'D', 'U', 'S', 'T', '-', 'E', 'N', 'D'" nocase ascii wide
                        $string14_CelestialSpark_offensive_tool_keyword = /x64\/CelestialSpark\.asm/ nocase ascii wide
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