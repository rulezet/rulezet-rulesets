rule rule_LOLSpoof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LOLSpoof_offensive_tool_keyword = "# Find LOLBin and reconstruct commandline" nocase ascii wide
                        $string2_LOLSpoof_offensive_tool_keyword = /\/lolbin\.exe/ nocase ascii wide
                        $string3_LOLSpoof_offensive_tool_keyword = /\/LOLSpoof\.git/ nocase ascii wide
                        $string4_LOLSpoof_offensive_tool_keyword = /\/LOLSpoof\.nim/ nocase ascii wide
                        $string5_LOLSpoof_offensive_tool_keyword = "/LOLSpoof/releases/download/" nocase ascii wide
                        $string6_LOLSpoof_offensive_tool_keyword = /\[LOLSpoof\]\s\>\s/ nocase ascii wide
                        $string7_LOLSpoof_offensive_tool_keyword = /\\lolbin\.exe/ nocase ascii wide
                        $string8_LOLSpoof_offensive_tool_keyword = /\\LOLSpoof\.nim/ nocase ascii wide
                        $string9_LOLSpoof_offensive_tool_keyword = /\\LOLSpoof\\/ nocase ascii wide
                        $string10_LOLSpoof_offensive_tool_keyword = "159766fade72711fc8b28004ec1f2088bb837852029f1e79446d728728c235ef" nocase ascii wide
                        $string11_LOLSpoof_offensive_tool_keyword = "8310f53135ddcc2e6b9fd6ca2aca3662f61dc1b5fb2b2510fa762e5862afcf94" nocase ascii wide
                        $string12_LOLSpoof_offensive_tool_keyword = "84f94c746a47d8bee6663a57051e15ce80f6847dc66733c31b1d793301814fcb" nocase ascii wide
                        $string13_LOLSpoof_offensive_tool_keyword = "An interactive shell to spoof some LOLBins" nocase ascii wide
                        $string14_LOLSpoof_offensive_tool_keyword = "Could not spoof binary: " nocase ascii wide
                        $string15_LOLSpoof_offensive_tool_keyword = "f8d85258f9c717fb629942c43b2218c96800252c3da18cbbc11839f790acc452" nocase ascii wide
                        $string16_LOLSpoof_offensive_tool_keyword = "itaymigdal/LOLSpoof" nocase ascii wide
                        $string17_LOLSpoof_offensive_tool_keyword = /lolbin\.exe\s/ nocase ascii wide
                        $string18_LOLSpoof_offensive_tool_keyword = /LOLSpoof\.exe/ nocase ascii wide

    condition:
        any of them
}