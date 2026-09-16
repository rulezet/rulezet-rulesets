rule rule_SharpNoPSExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpNoPSExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpNoPSExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpNoPSExec_offensive_tool_keyword = /\s\-\-target\=.{0,1000}\s\-\-payload\=.{0,1000}cmd\.exe\s\/c/ nocase ascii wide
                        $string2_SharpNoPSExec_offensive_tool_keyword = "/SharpNoPSExec" nocase ascii wide
                        $string3_SharpNoPSExec_offensive_tool_keyword = /\\SharpNoPSExec/ nocase ascii wide
                        $string4_SharpNoPSExec_offensive_tool_keyword = "acf7a8a9-3aaf-46c2-8aa8-2d12d7681baf" nocase ascii wide
                        $string5_SharpNoPSExec_offensive_tool_keyword = "-e ZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA=" nocase ascii wide
                        $string6_SharpNoPSExec_offensive_tool_keyword = /SharpNoPSExec\.csproj/ nocase ascii wide
                        $string7_SharpNoPSExec_offensive_tool_keyword = /SharpNoPSExec\.exe/ nocase ascii wide
                        $string8_SharpNoPSExec_offensive_tool_keyword = /SharpNoPSExec\.sln/ nocase ascii wide
                        $string9_SharpNoPSExec_offensive_tool_keyword = "SharpNoPSExec-master" nocase ascii wide

    condition:
        any of them
}