rule Ebowla
{
    meta:
        description = "Detection patterns for the tool 'Ebowla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ebowla"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sebowla\.py/ nocase ascii wide
                        $string2 = /\/Ebowla\.git/ nocase ascii wide
                        $string3 = /\/ebowla\.py/ nocase ascii wide
                        $string4 = /\\ebowla\.py/ nocase ascii wide
                        $string5 = /DllLoaderLoader\.exe/ nocase ascii wide
                        $string6 = /Ebowla\-master\.zip/ nocase ascii wide
                        $string7 = /exe_dll_shellcode\sgenetic\.config/ nocase ascii wide
                        $string8 = "Genetic-Malware/Ebowla" nocase ascii wide

    condition:
        any of them
}