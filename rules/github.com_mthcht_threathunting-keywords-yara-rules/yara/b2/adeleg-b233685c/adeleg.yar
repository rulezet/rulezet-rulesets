rule adeleg
{
    meta:
        description = "Detection patterns for the tool 'adeleg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adeleg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ADeleg\.exe/ nocase ascii wide
                        $string2 = /\/adeleg\.git/ nocase ascii wide
                        $string3 = /\/adeleg\.pdb/ nocase ascii wide
                        $string4 = /\\ADeleg\.exe/ nocase ascii wide
                        $string5 = /\\adeleg\.pdb/ nocase ascii wide
                        $string6 = /\\adeleg\\adeleg\\/ nocase ascii wide
                        $string7 = /\\adeleg\\winldap\\/ nocase ascii wide
                        $string8 = /\\adeleg\-main/ nocase ascii wide
                        $string9 = /ADeleg\.exe\s\-/ nocase ascii wide
                        $string10 = "mtth-bfft/adeleg" nocase ascii wide

    condition:
        any of them
}