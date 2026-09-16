rule rule_Bad_PDF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Bad-PDF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bad-PDF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Bad_PDF_offensive_tool_keyword = "Bad-Pdf" nocase ascii wide

    condition:
        any of them
}