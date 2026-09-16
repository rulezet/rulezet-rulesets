rule PassSpray
{
    meta:
        description = "Detection patterns for the tool 'PassSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPassSpray\.ps1/ nocase ascii wide
                        $string2 = /\/PassSpray\.git/ nocase ascii wide
                        $string3 = /\/PassSpray\.ps1/ nocase ascii wide
                        $string4 = /\\PassSpray\.ps1/ nocase ascii wide
                        $string5 = "24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f" nocase ascii wide
                        $string6 = "Invoke-PassSpray" nocase ascii wide
                        $string7 = "Leo4j/PassSpray" nocase ascii wide

    condition:
        any of them
}