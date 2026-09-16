rule rule_SharpTerminator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpTerminator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpTerminator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpTerminator_offensive_tool_keyword = /\.exe.{0,1000}\\Terminator\.sys/ nocase ascii wide
                        $string2_SharpTerminator_offensive_tool_keyword = "/SharpTerminator/" nocase ascii wide
                        $string3_SharpTerminator_offensive_tool_keyword = /\/terminate\/Terminator\.sys/ nocase ascii wide
                        $string4_SharpTerminator_offensive_tool_keyword = /\\SharpTerminator\.csproj/ nocase ascii wide
                        $string5_SharpTerminator_offensive_tool_keyword = /http.{0,1000}\:\/\/.{0,1000}\/Terminator\.sys/ nocase ascii wide
                        $string6_SharpTerminator_offensive_tool_keyword = "mertdas/SharpTerminator" nocase ascii wide
                        $string7_SharpTerminator_offensive_tool_keyword = /sc\screate\sTerminator\s.{0,1000}\.sys/ nocase ascii wide
                        $string8_SharpTerminator_offensive_tool_keyword = /SharpTerminator\.exe/ nocase ascii wide
                        $string9_SharpTerminator_offensive_tool_keyword = /SharpTerminator\.git/ nocase ascii wide
                        $string10_SharpTerminator_offensive_tool_keyword = /SharpTerminator\.sln/ nocase ascii wide
                        $string11_SharpTerminator_offensive_tool_keyword = /SharpTerminator\-main\.zip/ nocase ascii wide

    condition:
        any of them
}