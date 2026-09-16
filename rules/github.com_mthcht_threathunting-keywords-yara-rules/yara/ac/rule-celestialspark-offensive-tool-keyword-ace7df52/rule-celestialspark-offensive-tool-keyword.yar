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
                        $string10_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,1000}\\"Stardust\sSocket\sFailed\\"/ nocase ascii wide
                        $string11_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,1000}\\"Stardust\sSocket\sInitialization\\"/ nocase ascii wide
                        $string12_CelestialSpark_offensive_tool_keyword = /MessageBoxW\(.{0,1000}\\"We\sare\sall\smade\sof\sStardust\!\\"/ nocase ascii wide
                        $string13_CelestialSpark_offensive_tool_keyword = "'S', 'T', 'A', 'R', 'D', 'U', 'S', 'T', '-', 'E', 'N', 'D'" nocase ascii wide
                        $string14_CelestialSpark_offensive_tool_keyword = /x64\/CelestialSpark\.asm/ nocase ascii wide

    condition:
        any of them
}