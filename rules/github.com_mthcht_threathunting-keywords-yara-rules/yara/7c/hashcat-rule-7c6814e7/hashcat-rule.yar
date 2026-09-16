rule hashcat_rule
{
    meta:
        description = "Detection patterns for the tool 'hashcat-rule' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashcat-rule"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hashcat\-rule\.git/
                        $string2 = /\/password_ruled\.txt/
                        $string3 = "clem9669/hashcat-rule"
                        $string4 = /clem9669_case\.rule/
                        $string5 = /clem9669_large\.rule/
                        $string6 = /clem9669_medium\.rule/
                        $string7 = /clem9669_small\.rule/
                        $string8 = "hashcat-rule-master"

    condition:
        any of them
}