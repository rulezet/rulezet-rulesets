rule tricky_lnk
{
    meta:
        description = "Detection patterns for the tool 'tricky.lnk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tricky.lnk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stricky\.ps1/ nocase ascii wide
                        $string2 = /\stricky\.vbs/ nocase ascii wide
                        $string3 = /\stricky2\.ps1/ nocase ascii wide
                        $string4 = /\/tricky\.lnk\.git/ nocase ascii wide
                        $string5 = /\/tricky\.ps1/ nocase ascii wide
                        $string6 = /\/tricky\.vbs/ nocase ascii wide
                        $string7 = /\/tricky2\.ps1/ nocase ascii wide
                        $string8 = /\\Desktop\\FakeText\.lnk/ nocase ascii wide
                        $string9 = /\\notavirus\.exe/ nocase ascii wide
                        $string10 = /\\tricky\.lnk\\/ nocase ascii wide
                        $string11 = /\\tricky\.vbs/ nocase ascii wide
                        $string12 = /\\tricky2\.ps1/ nocase ascii wide
                        $string13 = "11fcbd067d55ddaa11e622be03a55ea342efe497cbcb14abf4dc410cb5d7a203" nocase ascii wide
                        $string14 = "676766b4b6296303a601cf2191da028cc39681fa69b1da408242882f760c849b" nocase ascii wide
                        $string15 = "9c9cc73f47b3b509df0845593e6b2f8d900f34772e4aaf3438bb0120303d5670" nocase ascii wide
                        $string16 = /xillwillx\/tricky\.lnk/ nocase ascii wide

    condition:
        any of them
}