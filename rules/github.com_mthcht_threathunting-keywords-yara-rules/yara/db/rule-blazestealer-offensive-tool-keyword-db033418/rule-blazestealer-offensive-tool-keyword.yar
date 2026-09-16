rule rule_BlazeStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BlazeStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlazeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BlazeStealer_offensive_tool_keyword = "/Pyobfadvance" nocase ascii wide
                        $string2_BlazeStealer_offensive_tool_keyword = "/Pyobfexecute" nocase ascii wide
                        $string3_BlazeStealer_offensive_tool_keyword = "/pyobfgood" nocase ascii wide
                        $string4_BlazeStealer_offensive_tool_keyword = "/Pyobflite" nocase ascii wide
                        $string5_BlazeStealer_offensive_tool_keyword = "/Pyobfpremium" nocase ascii wide
                        $string6_BlazeStealer_offensive_tool_keyword = "/Pyobftoexe" nocase ascii wide
                        $string7_BlazeStealer_offensive_tool_keyword = "/Pyobfuse" nocase ascii wide
                        $string8_BlazeStealer_offensive_tool_keyword = "/Pyobfusfile" nocase ascii wide
                        $string9_BlazeStealer_offensive_tool_keyword = /\\Pyobfadvance/ nocase ascii wide
                        $string10_BlazeStealer_offensive_tool_keyword = /\\Pyobfexecute/ nocase ascii wide
                        $string11_BlazeStealer_offensive_tool_keyword = /\\pyobfgood/ nocase ascii wide
                        $string12_BlazeStealer_offensive_tool_keyword = /\\Pyobflite/ nocase ascii wide
                        $string13_BlazeStealer_offensive_tool_keyword = /\\Pyobfpremium/ nocase ascii wide
                        $string14_BlazeStealer_offensive_tool_keyword = /\\Pyobftoexe/ nocase ascii wide
                        $string15_BlazeStealer_offensive_tool_keyword = /\\Pyobfuse/ nocase ascii wide
                        $string16_BlazeStealer_offensive_tool_keyword = /\\Pyobfusfile/ nocase ascii wide
                        $string17_BlazeStealer_offensive_tool_keyword = /MTE2NTc2MDM5MjY5NDM1NDA2MA\.GRSNK7\.OHxJIpJoZxopWpF_S3zy5v2g7k2vyiufQ183Lo/ nocase ascii wide

    condition:
        any of them
}