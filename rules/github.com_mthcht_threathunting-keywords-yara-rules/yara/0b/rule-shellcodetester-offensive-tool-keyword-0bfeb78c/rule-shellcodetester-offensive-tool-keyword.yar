rule rule_shellcodetester_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shellcodetester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shellcodetester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_shellcodetester_offensive_tool_keyword = "/shellcodetester" nocase ascii wide
                        $string2_shellcodetester_offensive_tool_keyword = "shellcodetester " nocase ascii wide
                        $string3_shellcodetester_offensive_tool_keyword = /ShellCodeTester\.csproj/ nocase ascii wide
                        $string4_shellcodetester_offensive_tool_keyword = /shellcodetester\.exe/ nocase ascii wide
                        $string5_shellcodetester_offensive_tool_keyword = /shellcodetester\.git/ nocase ascii wide
                        $string6_shellcodetester_offensive_tool_keyword = /shellcodetester\.sh/ nocase ascii wide
                        $string7_shellcodetester_offensive_tool_keyword = /ShellCodeTester\.sln/ nocase ascii wide

    condition:
        any of them
}