rule rule_RagingRotator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RagingRotator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RagingRotator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RagingRotator_offensive_tool_keyword = /\sRagingRotator\.go/ nocase ascii wide
                        $string2_RagingRotator_offensive_tool_keyword = /\s\-userpassfile\s\.\/userpass_file\.txt/
                        $string3_RagingRotator_offensive_tool_keyword = /\/RagingRotator\.git/ nocase ascii wide
                        $string4_RagingRotator_offensive_tool_keyword = /\/RagingRotator\.go/ nocase ascii wide
                        $string5_RagingRotator_offensive_tool_keyword = /\[\!\]\sValid\slogin.{0,1000}\sexpired\spassword\:\s/ nocase ascii wide
                        $string6_RagingRotator_offensive_tool_keyword = /\[\+\]\sValid\slogin.{0,1000}\suser\smust\senroll\sin\sMFA\./ nocase ascii wide
                        $string7_RagingRotator_offensive_tool_keyword = /\\RagingRotator\.go/ nocase ascii wide
                        $string8_RagingRotator_offensive_tool_keyword = "nickzer0/RagingRotator" nocase ascii wide
                        $string9_RagingRotator_offensive_tool_keyword = /RagingRotator\-main\./ nocase ascii wide

    condition:
        any of them
}