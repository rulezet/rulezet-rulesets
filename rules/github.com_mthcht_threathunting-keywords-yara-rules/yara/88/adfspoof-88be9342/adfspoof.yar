rule ADFSpoof
{
    meta:
        description = "Detection patterns for the tool 'ADFSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADFSpoof\.py/ nocase ascii wide
                        $string2 = /\s\-b\s.{0,1000}\.bin\s.{0,1000}\.bin\sdump/ nocase ascii wide
                        $string3 = /\/ADFSpoof\.py/ nocase ascii wide
                        $string4 = /\\ADFSpoof\.py/ nocase ascii wide
                        $string5 = "ADFSpoof-master" nocase ascii wide
                        $string6 = /EncryptedPfx\.py/ nocase ascii wide

    condition:
        any of them
}