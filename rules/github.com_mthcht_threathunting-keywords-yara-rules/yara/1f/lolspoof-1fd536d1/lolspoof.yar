rule LOLSpoof
{
    meta:
        description = "Detection patterns for the tool 'LOLSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LOLSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "# Find LOLBin and reconstruct commandline" nocase ascii wide
                        $string2 = /\/lolbin\.exe/ nocase ascii wide
                        $string3 = /\/LOLSpoof\.git/ nocase ascii wide
                        $string4 = /\/LOLSpoof\.nim/ nocase ascii wide
                        $string5 = "/LOLSpoof/releases/download/" nocase ascii wide
                        $string6 = /\[LOLSpoof\]\s\>\s/ nocase ascii wide
                        $string7 = /\\lolbin\.exe/ nocase ascii wide
                        $string8 = /\\LOLSpoof\.nim/ nocase ascii wide
                        $string9 = /\\LOLSpoof\\/ nocase ascii wide
                        $string10 = "159766fade72711fc8b28004ec1f2088bb837852029f1e79446d728728c235ef" nocase ascii wide
                        $string11 = "8310f53135ddcc2e6b9fd6ca2aca3662f61dc1b5fb2b2510fa762e5862afcf94" nocase ascii wide
                        $string12 = "84f94c746a47d8bee6663a57051e15ce80f6847dc66733c31b1d793301814fcb" nocase ascii wide
                        $string13 = "An interactive shell to spoof some LOLBins" nocase ascii wide
                        $string14 = "Could not spoof binary: " nocase ascii wide
                        $string15 = "f8d85258f9c717fb629942c43b2218c96800252c3da18cbbc11839f790acc452" nocase ascii wide
                        $string16 = "itaymigdal/LOLSpoof" nocase ascii wide
                        $string17 = /lolbin\.exe\s/ nocase ascii wide
                        $string18 = /LOLSpoof\.exe/ nocase ascii wide

    condition:
        any of them
}