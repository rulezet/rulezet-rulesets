rule rule_mimipy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mimipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mimipy_offensive_tool_keyword = /\smimipenguin\.sh/ nocase ascii wide
                        $string2_mimipy_offensive_tool_keyword = /\smimipy\.py\s/ nocase ascii wide
                        $string3_mimipy_offensive_tool_keyword = /\/mimipenguin\.sh/ nocase ascii wide
                        $string4_mimipy_offensive_tool_keyword = /\/mimipy\.git/ nocase ascii wide
                        $string5_mimipy_offensive_tool_keyword = "47042a24b908274eec6f075245339e4f6058834220e3c2469e235c881d8aa5eb" nocase ascii wide
                        $string6_mimipy_offensive_tool_keyword = "fc22650b89b63d52f14ec5d17c0ee92b1d897825c6b7eb3db391e18268567d25" nocase ascii wide
                        $string7_mimipy_offensive_tool_keyword = /loot_mysql_passwords\(/ nocase ascii wide
                        $string8_mimipy_offensive_tool_keyword = "mimipy_loot_passwords" nocase ascii wide
                        $string9_mimipy_offensive_tool_keyword = "n1nj4sec/mimipy" nocase ascii wide

    condition:
        any of them
}