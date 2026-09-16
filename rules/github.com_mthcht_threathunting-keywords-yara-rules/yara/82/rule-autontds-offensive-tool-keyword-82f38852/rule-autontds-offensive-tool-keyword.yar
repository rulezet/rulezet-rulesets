rule rule_autoNTDS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'autoNTDS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autoNTDS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_autoNTDS_offensive_tool_keyword = /\sautoNTDS\.py/ nocase ascii wide
                        $string2_autoNTDS_offensive_tool_keyword = /\s\-\-crack\s.{0,1000}\s\-\-ntds/ nocase ascii wide
                        $string3_autoNTDS_offensive_tool_keyword = /\s\-\-ntds\s.{0,1000}\s\-crack\s/ nocase ascii wide
                        $string4_autoNTDS_offensive_tool_keyword = /\s\-\-passwords\-to\-users\s.{0,1000}hash/ nocase ascii wide
                        $string5_autoNTDS_offensive_tool_keyword = /\/autoNTDS\.git/ nocase ascii wide
                        $string6_autoNTDS_offensive_tool_keyword = /\/autoNTDS\.py/ nocase ascii wide
                        $string7_autoNTDS_offensive_tool_keyword = /\/cracked\-users\.txt/ nocase ascii wide
                        $string8_autoNTDS_offensive_tool_keyword = /\\autoNTDS\.py/ nocase ascii wide
                        $string9_autoNTDS_offensive_tool_keyword = "5df2061e118e67da27199797b696b33b0176f35d155b2a1204b4fd11ea6d25bb" nocase ascii wide
                        $string10_autoNTDS_offensive_tool_keyword = "hmaverickadams/autoNTDS" nocase ascii wide
                        $string11_autoNTDS_offensive_tool_keyword = /Passwords\sto\susers\scomplete\.\sPlease\ssee\scracked\-users\.txt/ nocase ascii wide

    condition:
        any of them
}