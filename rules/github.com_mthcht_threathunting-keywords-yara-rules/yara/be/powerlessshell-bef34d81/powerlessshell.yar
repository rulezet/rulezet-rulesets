rule PowerLessShell
{
    meta:
        description = "Detection patterns for the tool 'PowerLessShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerLessShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /malicious\.csproj/ nocase ascii wide
                        $string2 = "PowerLessShell" nocase ascii wide
                        $string3 = /PowerLessShell\.py/ nocase ascii wide
                        $string4 = /shellcode_inject\.csproj/ nocase ascii wide

    condition:
        any of them
}