rule BlazeStealer
{
    meta:
        description = "Detection patterns for the tool 'BlazeStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlazeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Pyobfadvance" nocase ascii wide
                        $string2 = "/Pyobfexecute" nocase ascii wide
                        $string3 = "/pyobfgood" nocase ascii wide
                        $string4 = "/Pyobflite" nocase ascii wide
                        $string5 = "/Pyobfpremium" nocase ascii wide
                        $string6 = "/Pyobftoexe" nocase ascii wide
                        $string7 = "/Pyobfuse" nocase ascii wide
                        $string8 = "/Pyobfusfile" nocase ascii wide
                        $string9 = /\\Pyobfadvance/ nocase ascii wide
                        $string10 = /\\Pyobfexecute/ nocase ascii wide
                        $string11 = /\\pyobfgood/ nocase ascii wide
                        $string12 = /\\Pyobflite/ nocase ascii wide
                        $string13 = /\\Pyobfpremium/ nocase ascii wide
                        $string14 = /\\Pyobftoexe/ nocase ascii wide
                        $string15 = /\\Pyobfuse/ nocase ascii wide
                        $string16 = /\\Pyobfusfile/ nocase ascii wide
                        $string17 = /MTE2NTc2MDM5MjY5NDM1NDA2MA\.GRSNK7\.OHxJIpJoZxopWpF_S3zy5v2g7k2vyiufQ183Lo/ nocase ascii wide

    condition:
        any of them
}