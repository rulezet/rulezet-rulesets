rule rule_PredatorTheStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PredatorTheStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PredatorTheStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PredatorTheStealer_offensive_tool_keyword = /\/c\sping\s127\.0\.0\.1\s\&\&\sdel\s\\\\/ nocase ascii wide
                        $string2_PredatorTheStealer_offensive_tool_keyword = /\/PredatorTheStealer\.git/ nocase ascii wide
                        $string3_PredatorTheStealer_offensive_tool_keyword = /\\PredatorTheStealer\sDll\./ nocase ascii wide
                        $string4_PredatorTheStealer_offensive_tool_keyword = /\\PredatorTheStealer\./ nocase ascii wide
                        $string5_PredatorTheStealer_offensive_tool_keyword = /\\Stealing\.cpp/ nocase ascii wide
                        $string6_PredatorTheStealer_offensive_tool_keyword = /\\tor\\hidden_service\./ nocase ascii wide
                        $string7_PredatorTheStealer_offensive_tool_keyword = /\\tor\\onion_router\./ nocase ascii wide
                        $string8_PredatorTheStealer_offensive_tool_keyword = "190DFAEB-0288-4043-BE0E-3273FA653B52" nocase ascii wide
                        $string9_PredatorTheStealer_offensive_tool_keyword = "30444d3f4f3bedc5d6aac36ad4deb9ce32d2ac91eb0b30e590f702b06825f372" nocase ascii wide
                        $string10_PredatorTheStealer_offensive_tool_keyword = "99383be21201b97e739e06f5c89a815cd4a296030985505f238862aecbbb7a77" nocase ascii wide
                        $string11_PredatorTheStealer_offensive_tool_keyword = /BTW\si\suse\sARCH\.\sA\s\-\sJeffrey\sEpstein\.\sR\s\-\sdidnt\.\sC\s\-\skill\.\sH\s\-\shimself/ nocase ascii wide
                        $string12_PredatorTheStealer_offensive_tool_keyword = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" nocase ascii wide
                        $string13_PredatorTheStealer_offensive_tool_keyword = "SecUser1/PredatorTheStealer" nocase ascii wide

    condition:
        any of them
}