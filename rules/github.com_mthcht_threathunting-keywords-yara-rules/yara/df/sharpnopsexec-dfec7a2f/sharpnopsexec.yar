rule SharpNoPSExec
{
    meta:
        description = "Detection patterns for the tool 'SharpNoPSExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpNoPSExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-target\=.{0,1000}\s\-\-payload\=.{0,1000}cmd\.exe\s\/c/ nocase ascii wide
                        $string2 = "/SharpNoPSExec" nocase ascii wide
                        $string3 = /\\SharpNoPSExec/ nocase ascii wide
                        $string4 = "acf7a8a9-3aaf-46c2-8aa8-2d12d7681baf" nocase ascii wide
                        $string5 = "-e ZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA=" nocase ascii wide
                        $string6 = /SharpNoPSExec\.csproj/ nocase ascii wide
                        $string7 = /SharpNoPSExec\.exe/ nocase ascii wide
                        $string8 = /SharpNoPSExec\.sln/ nocase ascii wide
                        $string9 = "SharpNoPSExec-master" nocase ascii wide

    condition:
        any of them
}