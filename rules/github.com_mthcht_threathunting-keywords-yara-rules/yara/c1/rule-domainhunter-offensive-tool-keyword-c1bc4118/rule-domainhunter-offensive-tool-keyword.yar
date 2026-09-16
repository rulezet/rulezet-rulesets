rule rule_domainhunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'domainhunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domainhunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_domainhunter_offensive_tool_keyword = " domainhunter " nocase ascii wide
                        $string2_domainhunter_offensive_tool_keyword = /\s\-\-keyword\s.{0,1000}\s\-\-check\s\-\-ocr\s.{0,1000}\s\-\-alexa/ nocase ascii wide
                        $string3_domainhunter_offensive_tool_keyword = "/domainhunter" nocase ascii wide
                        $string4_domainhunter_offensive_tool_keyword = "domainhunter" nocase ascii wide
                        $string5_domainhunter_offensive_tool_keyword = /domainhunter\.py/ nocase ascii wide
                        $string6_domainhunter_offensive_tool_keyword = "downloadMalwareDomains" nocase ascii wide

    condition:
        any of them
}