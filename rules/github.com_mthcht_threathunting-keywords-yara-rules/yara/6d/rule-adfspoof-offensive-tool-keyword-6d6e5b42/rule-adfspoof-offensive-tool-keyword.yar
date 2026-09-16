rule rule_ADFSpoof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADFSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADFSpoof_offensive_tool_keyword = /\sADFSpoof\.py/ nocase ascii wide
                        $string2_ADFSpoof_offensive_tool_keyword = /\s\-b\s.{0,1000}\.bin\s.{0,1000}\.bin\sdump/ nocase ascii wide
                        $string3_ADFSpoof_offensive_tool_keyword = /\/ADFSpoof\.py/ nocase ascii wide
                        $string4_ADFSpoof_offensive_tool_keyword = /\\ADFSpoof\.py/ nocase ascii wide
                        $string5_ADFSpoof_offensive_tool_keyword = "ADFSpoof-master" nocase ascii wide
                        $string6_ADFSpoof_offensive_tool_keyword = /EncryptedPfx\.py/ nocase ascii wide

    condition:
        any of them
}