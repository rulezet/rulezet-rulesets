rule rule_petipotam_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'petipotam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "petipotam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_petipotam_offensive_tool_keyword = /\/PetitPotam\.exe/ nocase ascii wide
                        $string2_petipotam_offensive_tool_keyword = /\/PetitPotam\.git/ nocase ascii wide
                        $string3_petipotam_offensive_tool_keyword = /\[\-\]\sGot\sRPC_ACCESS_DENIED\!\!\sEfsRpcOpenFileRaw\sis\sprobably\sPATCHED\!/ nocase ascii wide
                        $string4_petipotam_offensive_tool_keyword = /\\PetitPotam\.exe/ nocase ascii wide
                        $string5_petipotam_offensive_tool_keyword = "3989cbea4af22774f0fa20d10b88c7247e675be8b9ec9dae716a44cb36d50189" nocase ascii wide
                        $string6_petipotam_offensive_tool_keyword = "D78924E1-7F2B-4315-A2D2-24124C7828F8" nocase ascii wide
                        $string7_petipotam_offensive_tool_keyword = /GILLES\sLionel\saka\stopotam\s\(\@topotam77\)/ nocase ascii wide
                        $string8_petipotam_offensive_tool_keyword = /PetitPotam\.cpp/ nocase ascii wide
                        $string9_petipotam_offensive_tool_keyword = /PetitPotam\.exe/ nocase ascii wide
                        $string10_petipotam_offensive_tool_keyword = /PetitPotam\.py/ nocase ascii wide
                        $string11_petipotam_offensive_tool_keyword = /PetitPotam\.sln/ nocase ascii wide
                        $string12_petipotam_offensive_tool_keyword = "PetitPotam:main" nocase ascii wide
                        $string13_petipotam_offensive_tool_keyword = /topotam\.exe/ nocase ascii wide
                        $string14_petipotam_offensive_tool_keyword = "topotam/PetitPotam" nocase ascii wide

    condition:
        any of them
}