rule rule_tricky_lnk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tricky.lnk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tricky.lnk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_tricky_lnk_offensive_tool_keyword = /\stricky\.ps1/ nocase ascii wide
                        $string2_tricky_lnk_offensive_tool_keyword = /\stricky\.vbs/ nocase ascii wide
                        $string3_tricky_lnk_offensive_tool_keyword = /\stricky2\.ps1/ nocase ascii wide
                        $string4_tricky_lnk_offensive_tool_keyword = /\/tricky\.lnk\.git/ nocase ascii wide
                        $string5_tricky_lnk_offensive_tool_keyword = /\/tricky\.ps1/ nocase ascii wide
                        $string6_tricky_lnk_offensive_tool_keyword = /\/tricky\.vbs/ nocase ascii wide
                        $string7_tricky_lnk_offensive_tool_keyword = /\/tricky2\.ps1/ nocase ascii wide
                        $string8_tricky_lnk_offensive_tool_keyword = /\\Desktop\\FakeText\.lnk/ nocase ascii wide
                        $string9_tricky_lnk_offensive_tool_keyword = /\\notavirus\.exe/ nocase ascii wide
                        $string10_tricky_lnk_offensive_tool_keyword = /\\tricky\.lnk\\/ nocase ascii wide
                        $string11_tricky_lnk_offensive_tool_keyword = /\\tricky\.vbs/ nocase ascii wide
                        $string12_tricky_lnk_offensive_tool_keyword = /\\tricky2\.ps1/ nocase ascii wide
                        $string13_tricky_lnk_offensive_tool_keyword = "11fcbd067d55ddaa11e622be03a55ea342efe497cbcb14abf4dc410cb5d7a203" nocase ascii wide
                        $string14_tricky_lnk_offensive_tool_keyword = "676766b4b6296303a601cf2191da028cc39681fa69b1da408242882f760c849b" nocase ascii wide
                        $string15_tricky_lnk_offensive_tool_keyword = "9c9cc73f47b3b509df0845593e6b2f8d900f34772e4aaf3438bb0120303d5670" nocase ascii wide
                        $string16_tricky_lnk_offensive_tool_keyword = /xillwillx\/tricky\.lnk/ nocase ascii wide

    condition:
        any of them
}