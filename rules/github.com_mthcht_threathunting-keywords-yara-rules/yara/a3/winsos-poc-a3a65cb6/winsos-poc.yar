rule winsos_poc
{
    meta:
        description = "Detection patterns for the tool 'winsos-poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winsos-poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/src\/winsos\.cpp/ nocase ascii wide
                        $string2 = /\/winsos\.exe/ nocase ascii wide
                        $string3 = /\/winsos\-poc\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sThe\sDLL\shas\sbeen\sinjected\sinto\sngentask\.exe\svia\sDLL\sSide\-Loading/ nocase ascii wide
                        $string5 = /\[x\]\sFailed\sto\slocate\sthe\sngentask\.exe\sbinary\sin\sthe\sWinSxS\sdirectory/ nocase ascii wide
                        $string6 = /\\winsos\.cpp/ nocase ascii wide
                        $string7 = /\\winsos\.exe/ nocase ascii wide
                        $string8 = /http\:\/\/127\.0\.0\.1\:8080\/target\.dll/ nocase ascii wide
                        $string9 = "thiagopeixoto/winsos-poc" nocase ascii wide

    condition:
        any of them
}