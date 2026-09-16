rule rule_winsos_poc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'winsos-poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winsos-poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_winsos_poc_offensive_tool_keyword = /\/src\/winsos\.cpp/ nocase ascii wide
                        $string2_winsos_poc_offensive_tool_keyword = /\/winsos\.exe/ nocase ascii wide
                        $string3_winsos_poc_offensive_tool_keyword = /\/winsos\-poc\.git/ nocase ascii wide
                        $string4_winsos_poc_offensive_tool_keyword = /\[\+\]\sThe\sDLL\shas\sbeen\sinjected\sinto\sngentask\.exe\svia\sDLL\sSide\-Loading/ nocase ascii wide
                        $string5_winsos_poc_offensive_tool_keyword = /\[x\]\sFailed\sto\slocate\sthe\sngentask\.exe\sbinary\sin\sthe\sWinSxS\sdirectory/ nocase ascii wide
                        $string6_winsos_poc_offensive_tool_keyword = /\\winsos\.cpp/ nocase ascii wide
                        $string7_winsos_poc_offensive_tool_keyword = /\\winsos\.exe/ nocase ascii wide
                        $string8_winsos_poc_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\:8080\/target\.dll/ nocase ascii wide
                        $string9_winsos_poc_offensive_tool_keyword = "thiagopeixoto/winsos-poc" nocase ascii wide

    condition:
        any of them
}