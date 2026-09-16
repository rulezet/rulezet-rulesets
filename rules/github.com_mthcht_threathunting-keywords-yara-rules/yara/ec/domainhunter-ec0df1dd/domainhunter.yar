rule domainhunter
{
    meta:
        description = "Detection patterns for the tool 'domainhunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domainhunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " domainhunter " nocase ascii wide
                        $string2 = /\s\-\-keyword\s.{0,1000}\s\-\-check\s\-\-ocr\s.{0,1000}\s\-\-alexa/ nocase ascii wide
                        $string3 = "/domainhunter" nocase ascii wide
                        $string4 = "domainhunter" nocase ascii wide
                        $string5 = /domainhunter\.py/ nocase ascii wide
                        $string6 = "downloadMalwareDomains" nocase ascii wide

    condition:
        any of them
}