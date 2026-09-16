rule rule_SchTask_0x727_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SchTask_0x727' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SchTask_0x727"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SchTask_0x727_offensive_tool_keyword = /\/SchTask\.zip/ nocase ascii wide
                        $string2_SchTask_0x727_offensive_tool_keyword = /\/SchTask_0x727\.git/ nocase ascii wide
                        $string3_SchTask_0x727_offensive_tool_keyword = "/SchTask_0x727/" nocase ascii wide
                        $string4_SchTask_0x727_offensive_tool_keyword = /\\bin\\Release\\SchTask\.exe/ nocase ascii wide
                        $string5_SchTask_0x727_offensive_tool_keyword = /\\SchTask\.sln/ nocase ascii wide
                        $string6_SchTask_0x727_offensive_tool_keyword = /\\SchTask\.zip/ nocase ascii wide
                        $string7_SchTask_0x727_offensive_tool_keyword = /\\SchTask_0x727\\/ nocase ascii wide
                        $string8_SchTask_0x727_offensive_tool_keyword = /\]\sHidden\stask\sxml\sfile\:\s/ nocase ascii wide
                        $string9_SchTask_0x727_offensive_tool_keyword = "0790530e1e0f1ed73b2b6fd701d75a2409c785af5367304d5fdd5bdfdf7eae46" nocase ascii wide
                        $string10_SchTask_0x727_offensive_tool_keyword = "0x727/SchTask_0x727" nocase ascii wide
                        $string11_SchTask_0x727_offensive_tool_keyword = "24aae23bcf8b0a513988d69b1526eebd791007136a1faf08ea1df5a8d3884e50" nocase ascii wide
                        $string12_SchTask_0x727_offensive_tool_keyword = "70c104eb31780222a3a882a3728cafeeb308d8ff718a5c9ce62778d579b3de86" nocase ascii wide
                        $string13_SchTask_0x727_offensive_tool_keyword = "b26b8713dc24bec3c5b0be456a1bbc058a8450c280d614695a691fa13ac6dbfd" nocase ascii wide
                        $string14_SchTask_0x727_offensive_tool_keyword = "E61C950E-A03D-40E2-AAD5-304C48570364" nocase ascii wide
                        $string15_SchTask_0x727_offensive_tool_keyword = "fe1ae959f9af863a11cefad541eb791a01e5bb9931cf5c57e478236ddad92ae6" nocase ascii wide
                        $string16_SchTask_0x727_offensive_tool_keyword = /SchTask\.exe\sC\:\\Windows\\System32\\cmd\.exe\s/ nocase ascii wide
                        $string17_SchTask_0x727_offensive_tool_keyword = "SchTask_0x727/releases" nocase ascii wide

    condition:
        any of them
}