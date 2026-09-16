rule rule_PowerLessShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerLessShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerLessShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerLessShell_offensive_tool_keyword = /malicious\.csproj/ nocase ascii wide
                        $string2_PowerLessShell_offensive_tool_keyword = "PowerLessShell" nocase ascii wide
                        $string3_PowerLessShell_offensive_tool_keyword = /PowerLessShell\.py/ nocase ascii wide
                        $string4_PowerLessShell_offensive_tool_keyword = /shellcode_inject\.csproj/ nocase ascii wide

    condition:
        any of them
}