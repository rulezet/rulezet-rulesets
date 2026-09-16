rule shellcodetester
{
    meta:
        description = "Detection patterns for the tool 'shellcodetester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shellcodetester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/shellcodetester" nocase ascii wide
                        $string2 = "shellcodetester " nocase ascii wide
                        $string3 = /ShellCodeTester\.csproj/ nocase ascii wide
                        $string4 = /shellcodetester\.exe/ nocase ascii wide
                        $string5 = /shellcodetester\.git/ nocase ascii wide
                        $string6 = /shellcodetester\.sh/ nocase ascii wide
                        $string7 = /ShellCodeTester\.sln/ nocase ascii wide

    condition:
        any of them
}