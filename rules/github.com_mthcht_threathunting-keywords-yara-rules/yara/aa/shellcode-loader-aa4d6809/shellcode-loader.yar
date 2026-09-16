rule Shellcode_Loader
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Loader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Loader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Shellcode\-Loader\.git/ nocase ascii wide
                        $string2 = /C\:\\Windows\\DirectX\.log.{0,1000}\\Windows\\Temp\\backup\.log/ nocase ascii wide
                        $string3 = "ReversingID/Shellcode-Loader" nocase ascii wide
                        $string4 = "Shellcode-Loader-master" nocase ascii wide

    condition:
        any of them
}