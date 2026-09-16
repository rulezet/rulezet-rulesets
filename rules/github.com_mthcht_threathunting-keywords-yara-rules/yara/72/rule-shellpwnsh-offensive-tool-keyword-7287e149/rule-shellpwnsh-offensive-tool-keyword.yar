rule rule_ShellPwnsh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellPwnsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellPwnsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellPwnsh_offensive_tool_keyword = /\.\/ShellPwnsh/
                        $string2_ShellPwnsh_offensive_tool_keyword = /\/ShellPwnsh\.git/ nocase ascii wide
                        $string3_ShellPwnsh_offensive_tool_keyword = /\\ShellPwnsh\-main/ nocase ascii wide
                        $string4_ShellPwnsh_offensive_tool_keyword = "32c3b62e05eb08f482b00ca28bca9b43d743048f287e9b42193df91d6ddcd09a" nocase ascii wide
                        $string5_ShellPwnsh_offensive_tool_keyword = "7e40488e6ce8545eccdcfd13124e609ff74c50a9ce89bc88b9b2b50862efda9c" nocase ascii wide
                        $string6_ShellPwnsh_offensive_tool_keyword = "9374f1f361c8c664f4527cc9e43e277fddab0bfc032e254fec9b22405210f808" nocase ascii wide
                        $string7_ShellPwnsh_offensive_tool_keyword = "BlackShell256/ShellPwnsh" nocase ascii wide
                        $string8_ShellPwnsh_offensive_tool_keyword = /FUD\sPayload\sGenerator\sby\sBlack\$hell256/ nocase ascii wide
                        $string9_ShellPwnsh_offensive_tool_keyword = /Generador\sde\sPayloads\sFUD\sby\sBlack\$hell256/ nocase ascii wide
                        $string10_ShellPwnsh_offensive_tool_keyword = /ShellPwnsh\.exe/ nocase ascii wide
                        $string11_ShellPwnsh_offensive_tool_keyword = /ShellPwnsh\.go/ nocase ascii wide
                        $string12_ShellPwnsh_offensive_tool_keyword = /System\.Net\.\$\(\[Text\.Encoding\]\:\:Unicode\.GetString\(\[Convert\]\:\:FromBase64String\(/ nocase ascii wide
                        $string13_ShellPwnsh_offensive_tool_keyword = /\'UwBvAGM\'\;\s\$xd\s\=\s\'AawBlA\'/ nocase ascii wide

    condition:
        any of them
}