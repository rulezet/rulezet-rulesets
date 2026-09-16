rule rule_Shellcode_Loader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Loader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Loader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shellcode_Loader_offensive_tool_keyword = /\/Shellcode\-Loader\.git/ nocase ascii wide
                        $string2_Shellcode_Loader_offensive_tool_keyword = /C\:\\Windows\\DirectX\.log.{0,1000}\\Windows\\Temp\\backup\.log/ nocase ascii wide
                        $string3_Shellcode_Loader_offensive_tool_keyword = "ReversingID/Shellcode-Loader" nocase ascii wide
                        $string4_Shellcode_Loader_offensive_tool_keyword = "Shellcode-Loader-master" nocase ascii wide

    condition:
        any of them
}