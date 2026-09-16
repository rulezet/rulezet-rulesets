rule PredatorTheStealer
{
    meta:
        description = "Detection patterns for the tool 'PredatorTheStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PredatorTheStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/c\sping\s127\.0\.0\.1\s\&\&\sdel\s\\\\/ nocase ascii wide
                        $string2 = /\/PredatorTheStealer\.git/ nocase ascii wide
                        $string3 = /\\PredatorTheStealer\sDll\./ nocase ascii wide
                        $string4 = /\\PredatorTheStealer\./ nocase ascii wide
                        $string5 = /\\Stealing\.cpp/ nocase ascii wide
                        $string6 = /\\tor\\hidden_service\./ nocase ascii wide
                        $string7 = /\\tor\\onion_router\./ nocase ascii wide
                        $string8 = "190DFAEB-0288-4043-BE0E-3273FA653B52" nocase ascii wide
                        $string9 = "30444d3f4f3bedc5d6aac36ad4deb9ce32d2ac91eb0b30e590f702b06825f372" nocase ascii wide
                        $string10 = "99383be21201b97e739e06f5c89a815cd4a296030985505f238862aecbbb7a77" nocase ascii wide
                        $string11 = /BTW\si\suse\sARCH\.\sA\s\-\sJeffrey\sEpstein\.\sR\s\-\sdidnt\.\sC\s\-\skill\.\sH\s\-\shimself/ nocase ascii wide
                        $string12 = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" nocase ascii wide
                        $string13 = "SecUser1/PredatorTheStealer" nocase ascii wide

    condition:
        any of them
}