rule rule_PayGen_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PayGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PayGen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PayGen_offensive_tool_keyword = /\/signer\-exe\.py/ nocase ascii wide
                        $string2_PayGen_offensive_tool_keyword = /PayGen.{0,1000}python3\sgenerate\.py/ nocase ascii wide
                        $string3_PayGen_offensive_tool_keyword = /shellcode\-exec\.ps1/ nocase ascii wide
                        $string4_PayGen_offensive_tool_keyword = /shellcode\-runner\.py/ nocase ascii wide
                        $string5_PayGen_offensive_tool_keyword = "youhacker55/PayGen" nocase ascii wide
                        $string6_PayGen_offensive_tool_keyword = "cd PayGen" nocase ascii wide

    condition:
        any of them
}