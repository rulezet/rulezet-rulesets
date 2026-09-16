rule CelestialSpark
{
    meta:
        description = "Detection patterns for the tool 'CelestialSpark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CelestialSpark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "// A: the Meterpreter stage is a large shellcode " nocase ascii wide
                        $string2 = /\/\/\sDefine\sIP\sAdress\sof\syour\sC2\sStager\s\(\!\)/ nocase ascii wide
                        $string3 = /\/CelestialSpark\.git/ nocase ascii wide
                        $string4 = /\[\!\]\sFailed\sto\sload\sshellcode\sinto\smemory/ nocase ascii wide
                        $string5 = /\\asm_CelestialSpark\.x64\.o/ nocase ascii wide
                        $string6 = /\\loader\.x64\.exe/ nocase ascii wide
                        $string7 = "482002c785db1a3432ec214464a19042a3f36a21e5617a9901a0eae9f04451f1" nocase ascii wide
                        $string8 = "b8c9caeda6743d224835019b8bdc0105ad54f9a804a33e7e51acb605a8e8bc25" nocase ascii wide
                        $string9 = "Karkas66/CelestialSpark" nocase ascii wide
                        $string10 = /MessageBoxW\(.{0,1000}\\"Stardust\sSocket\sFailed\\"/ nocase ascii wide
                        $string11 = /MessageBoxW\(.{0,1000}\\"Stardust\sSocket\sInitialization\\"/ nocase ascii wide
                        $string12 = /MessageBoxW\(.{0,1000}\\"We\sare\sall\smade\sof\sStardust\!\\"/ nocase ascii wide
                        $string13 = "'S', 'T', 'A', 'R', 'D', 'U', 'S', 'T', '-', 'E', 'N', 'D'" nocase ascii wide
                        $string14 = /x64\/CelestialSpark\.asm/ nocase ascii wide

    condition:
        any of them
}