rule EmailAll
{
    meta:
        description = "Detection patterns for the tool 'EmailAll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmailAll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-domains\s\.\/domains\.txt\srun/
                        $string2 = /\semailall\.py/ nocase ascii wide
                        $string3 = /\/EmailAll\.git/ nocase ascii wide
                        $string4 = /\/emailall\.py/ nocase ascii wide
                        $string5 = /\\emailall\.py/ nocase ascii wide
                        $string6 = /emailall\.py\s\-/ nocase ascii wide
                        $string7 = /emailall\.py\scheck/ nocase ascii wide
                        $string8 = /EmailAll\-master\./ nocase ascii wide
                        $string9 = "Taonn/EmailAll" nocase ascii wide

    condition:
        any of them
}