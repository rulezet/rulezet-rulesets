rule petipotam
{
    meta:
        description = "Detection patterns for the tool 'petipotam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "petipotam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PetitPotam\.exe/ nocase ascii wide
                        $string2 = /\/PetitPotam\.git/ nocase ascii wide
                        $string3 = /\[\-\]\sGot\sRPC_ACCESS_DENIED\!\!\sEfsRpcOpenFileRaw\sis\sprobably\sPATCHED\!/ nocase ascii wide
                        $string4 = /\\PetitPotam\.exe/ nocase ascii wide
                        $string5 = "3989cbea4af22774f0fa20d10b88c7247e675be8b9ec9dae716a44cb36d50189" nocase ascii wide
                        $string6 = "D78924E1-7F2B-4315-A2D2-24124C7828F8" nocase ascii wide
                        $string7 = /GILLES\sLionel\saka\stopotam\s\(\@topotam77\)/ nocase ascii wide
                        $string8 = /PetitPotam\.cpp/ nocase ascii wide
                        $string9 = /PetitPotam\.exe/ nocase ascii wide
                        $string10 = /PetitPotam\.py/ nocase ascii wide
                        $string11 = /PetitPotam\.sln/ nocase ascii wide
                        $string12 = "PetitPotam:main" nocase ascii wide
                        $string13 = /topotam\.exe/ nocase ascii wide
                        $string14 = "topotam/PetitPotam" nocase ascii wide

    condition:
        any of them
}