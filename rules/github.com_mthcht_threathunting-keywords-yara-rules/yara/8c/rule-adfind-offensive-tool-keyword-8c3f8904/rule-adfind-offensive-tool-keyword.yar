rule rule_adfind_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adfind_offensive_tool_keyword = "adfind -gcb -sc trustdmp" nocase ascii wide
                        $string2_adfind_offensive_tool_keyword = "adfind -sc adinfo" nocase ascii wide
                        $string3_adfind_offensive_tool_keyword = "adfind -sc computers_pwdnotreqd" nocase ascii wide
                        $string4_adfind_offensive_tool_keyword = "adfind -sc dclist" nocase ascii wide
                        $string5_adfind_offensive_tool_keyword = "adfind -sc dcmodes" nocase ascii wide
                        $string6_adfind_offensive_tool_keyword = "adfind -sc domainlist" nocase ascii wide
                        $string7_adfind_offensive_tool_keyword = "adfind -sc trustdmp" nocase ascii wide
                        $string8_adfind_offensive_tool_keyword = "adfind -subnets" nocase ascii wide
                        $string9_adfind_offensive_tool_keyword = /adfind\.exe\s\-f\s\(objectcategory\=organizationalUnit\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string10_adfind_offensive_tool_keyword = /adfind\.exe\s\-f\s\(objectcategory\=person\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string11_adfind_offensive_tool_keyword = /adfind\.exe\s\-f\s.{0,1000}\(objectcategory\=group\).{0,1000}\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string12_adfind_offensive_tool_keyword = /adfind\.exe\s\-f\sobjectcategory\=computer\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string13_adfind_offensive_tool_keyword = /adfind\.exe\s\-gcb\s\-sc\strustdmp\s\>\s.{0,1000}\.txt/ nocase ascii wide
                        $string14_adfind_offensive_tool_keyword = /adfind\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}