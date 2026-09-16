rule rule_SharpExShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpExShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpExShell_offensive_tool_keyword = /\/SharpExcelDCom\.exe/ nocase ascii wide
                        $string2_SharpExShell_offensive_tool_keyword = /\/SharpExShell\.exe/ nocase ascii wide
                        $string3_SharpExShell_offensive_tool_keyword = /\/SharpExShell\.git/ nocase ascii wide
                        $string4_SharpExShell_offensive_tool_keyword = /\\SharpExcelDCom\.exe/ nocase ascii wide
                        $string5_SharpExShell_offensive_tool_keyword = /\\SharpExShell\.exe/ nocase ascii wide
                        $string6_SharpExShell_offensive_tool_keyword = /\\SharpExShell\.sln/ nocase ascii wide
                        $string7_SharpExShell_offensive_tool_keyword = "13C84182-2F5F-4EE8-A37A-4483E7E57154" nocase ascii wide
                        $string8_SharpExShell_offensive_tool_keyword = "37618f36a162e667eb98cb36bc1568524f87efc7cc12ef6d0ea4ef2f225c799d" nocase ascii wide
                        $string9_SharpExShell_offensive_tool_keyword = "4848f468fc1f6b5c933d83be4e9295cf6af8eb74b789fdf0a6f116c7444808b2" nocase ascii wide
                        $string10_SharpExShell_offensive_tool_keyword = "a63bf8aa62471b0cb62919e6e387482895a8027d5f763aba5f76572a595d7a31" nocase ascii wide
                        $string11_SharpExShell_offensive_tool_keyword = "grayhatkiller/SharpExShell" nocase ascii wide

    condition:
        any of them
}