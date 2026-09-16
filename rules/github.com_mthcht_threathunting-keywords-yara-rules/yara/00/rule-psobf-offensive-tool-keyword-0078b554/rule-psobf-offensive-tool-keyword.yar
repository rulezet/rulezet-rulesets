rule rule_psobf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psobf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psobf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_psobf_offensive_tool_keyword = /\.\/obfuscator\s\-i\s.{0,1000}\.ps1/
                        $string2_psobf_offensive_tool_keyword = /\/psobf\.git/ nocase ascii wide
                        $string3_psobf_offensive_tool_keyword = "f3b1f6c6ca346acab1afd2dc61c43588f4c0914c1a6d1247db3a46bbd3421b38" nocase ascii wide
                        $string4_psobf_offensive_tool_keyword = /Invoke\-Expression\s\$obfuscated/ nocase ascii wide
                        $string5_psobf_offensive_tool_keyword = "TaurusOmar/psobf" nocase ascii wide

    condition:
        any of them
}