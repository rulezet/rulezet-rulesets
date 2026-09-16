rule rule_ShellServe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellServe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellServe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellServe_offensive_tool_keyword = /\/ShellServe\.git/ nocase ascii wide
                        $string2_ShellServe_offensive_tool_keyword = "@author 7etsuo" nocase ascii wide
                        $string3_ShellServe_offensive_tool_keyword = "7c8c4d1e312218cb8a31c00d67f3b5e2e752d9e094e37c959e35e0483fc69109" nocase ascii wide
                        $string4_ShellServe_offensive_tool_keyword = "7etsuo/ShellServe" nocase ascii wide
                        $string5_ShellServe_offensive_tool_keyword = "d1f5e8ada7197e67b7bdede4827104e286c63f24407bb9eef80cc7c2bd2e065f" nocase ascii wide
                        $string6_ShellServe_offensive_tool_keyword = "edaa2e28eee643e72776396155001db13f288d9bc64e57057127a09c1d57c9a7" nocase ascii wide
                        $string7_ShellServe_offensive_tool_keyword = /load_credentials\(\\"credentials\.txt\\"\)/ nocase ascii wide

    condition:
        any of them
}