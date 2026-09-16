rule rule_ShellGen_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellGen_offensive_tool_keyword = /\sShellGen\.ps1/ nocase ascii wide
                        $string2_ShellGen_offensive_tool_keyword = /\$B64PwshCommand/ nocase ascii wide
                        $string3_ShellGen_offensive_tool_keyword = /\$shellcode\s\+\=\s0x65\,0x48\,0x8b\,0x42\,0x60/ nocase ascii wide
                        $string4_ShellGen_offensive_tool_keyword = /\/ShellGen\.git/ nocase ascii wide
                        $string5_ShellGen_offensive_tool_keyword = /\/ShellGen\.ps1/ nocase ascii wide
                        $string6_ShellGen_offensive_tool_keyword = /\\ShellGen\.ps1/ nocase ascii wide
                        $string7_ShellGen_offensive_tool_keyword = /\\ShellGen\-main\.zip/ nocase ascii wide
                        $string8_ShellGen_offensive_tool_keyword = "59c03a973a4c6ad7327812d568a8bcdd9c21af006853ce459014183bef699a24" nocase ascii wide
                        $string9_ShellGen_offensive_tool_keyword = "Leo4j/ShellGen" nocase ascii wide
                        $string10_ShellGen_offensive_tool_keyword = "ShellGen -x64 -B64PwshCommand " nocase ascii wide
                        $string11_ShellGen_offensive_tool_keyword = "ShellGen -x64 -CmdCommand " nocase ascii wide
                        $string12_ShellGen_offensive_tool_keyword = "ShellGen -x64 -PwshCommand " nocase ascii wide

    condition:
        any of them
}