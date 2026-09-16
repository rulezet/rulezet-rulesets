rule RagingRotator
{
    meta:
        description = "Detection patterns for the tool 'RagingRotator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RagingRotator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sRagingRotator\.go/ nocase ascii wide
                        $string2 = /\s\-userpassfile\s\.\/userpass_file\.txt/
                        $string3 = /\/RagingRotator\.git/ nocase ascii wide
                        $string4 = /\/RagingRotator\.go/ nocase ascii wide
                        $string5 = /\[\!\]\sValid\slogin.{0,1000}\sexpired\spassword\:\s/ nocase ascii wide
                        $string6 = /\[\+\]\sValid\slogin.{0,1000}\suser\smust\senroll\sin\sMFA\./ nocase ascii wide
                        $string7 = /\\RagingRotator\.go/ nocase ascii wide
                        $string8 = "nickzer0/RagingRotator" nocase ascii wide
                        $string9 = /RagingRotator\-main\./ nocase ascii wide

    condition:
        any of them
}