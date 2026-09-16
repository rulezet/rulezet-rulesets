rule Shhhloader
{
    meta:
        description = "Detection patterns for the tool 'Shhhloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shhhloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sShhhavoc\.py/ nocase ascii wide
                        $string2 = /\/Shhhavoc\.py/ nocase ascii wide
                        $string3 = /\/Shhhloader\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sICYGUIDER\'S\sCUSTOM\sSYSCALL\sSHELLCODE\sLOADER/ nocase ascii wide
                        $string5 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string6 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string7 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string8 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string9 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub/ nocase ascii wide
                        $string10 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string11 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string12 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string13 = /\\Shhhavoc\.py/ nocase ascii wide
                        $string14 = "icyguider/Shhhloader" nocase ascii wide
                        $string15 = /Shhhavoc\.py\s/ nocase ascii wide
                        $string16 = /Shhhloader\.py/ nocase ascii wide
                        $string17 = /Shhhloader\-main\\/ nocase ascii wide

    condition:
        any of them
}