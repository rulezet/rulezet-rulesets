rule rule_Shhhloader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shhhloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shhhloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shhhloader_offensive_tool_keyword = /\sShhhavoc\.py/ nocase ascii wide
                        $string2_Shhhloader_offensive_tool_keyword = /\/Shhhavoc\.py/ nocase ascii wide
                        $string3_Shhhloader_offensive_tool_keyword = /\/Shhhloader\.git/ nocase ascii wide
                        $string4_Shhhloader_offensive_tool_keyword = /\[\+\]\sICYGUIDER\'S\sCUSTOM\sSYSCALL\sSHELLCODE\sLOADER/ nocase ascii wide
                        $string5_Shhhloader_offensive_tool_keyword = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
                        $string6_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string7_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string8_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string9_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub/ nocase ascii wide
                        $string10_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string11_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
                        $string12_Shhhloader_offensive_tool_keyword = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
                        $string13_Shhhloader_offensive_tool_keyword = /\\Shhhavoc\.py/ nocase ascii wide
                        $string14_Shhhloader_offensive_tool_keyword = "icyguider/Shhhloader" nocase ascii wide
                        $string15_Shhhloader_offensive_tool_keyword = /Shhhavoc\.py\s/ nocase ascii wide
                        $string16_Shhhloader_offensive_tool_keyword = /Shhhloader\.py/ nocase ascii wide
                        $string17_Shhhloader_offensive_tool_keyword = /Shhhloader\-main\\/ nocase ascii wide

    condition:
        any of them
}