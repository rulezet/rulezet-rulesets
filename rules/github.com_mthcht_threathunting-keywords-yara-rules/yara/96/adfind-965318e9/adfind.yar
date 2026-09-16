rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "adfind -gcb -sc trustdmp" nocase ascii wide
                        $string2 = "adfind -sc adinfo" nocase ascii wide
                        $string3 = "adfind -sc computers_pwdnotreqd" nocase ascii wide
                        $string4 = "adfind -sc dclist" nocase ascii wide
                        $string5 = "adfind -sc dcmodes" nocase ascii wide
                        $string6 = "adfind -sc domainlist" nocase ascii wide
                        $string7 = "adfind -sc trustdmp" nocase ascii wide
                        $string8 = "adfind -subnets" nocase ascii wide
                        $string9 = /adfind\.exe\s\-f\s\(objectcategory\=organizationalUnit\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string10 = /adfind\.exe\s\-f\s\(objectcategory\=person\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string11 = /adfind\.exe\s\-f\s.{0,1000}\(objectcategory\=group\).{0,1000}\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string12 = /adfind\.exe\s\-f\sobjectcategory\=computer\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string13 = /adfind\.exe\s\-gcb\s\-sc\strustdmp\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string14 = /adfind\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}