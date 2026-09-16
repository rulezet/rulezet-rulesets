rule Bad_PDF
{
    meta:
        description = "Detection patterns for the tool 'Bad-PDF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bad-PDF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Bad-Pdf" nocase ascii wide

    condition:
        any of them
}