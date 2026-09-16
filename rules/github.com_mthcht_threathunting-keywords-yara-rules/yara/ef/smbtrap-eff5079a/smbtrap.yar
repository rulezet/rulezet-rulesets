rule SMBTrap
{
    meta:
        description = "Detection patterns for the tool 'SMBTrap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBTrap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\squickcrack\.py/ nocase ascii wide
                        $string2 = /\sredirecttosmb\.py/ nocase ascii wide
                        $string3 = /\ssmbtrap2\.py/ nocase ascii wide
                        $string4 = /\ssmbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string5 = /\/quickcrack\.py/ nocase ascii wide
                        $string6 = /\/redirecttosmb\.py/ nocase ascii wide
                        $string7 = /\/SMBTrap\.git/ nocase ascii wide
                        $string8 = /\/smbtrap2\.py/ nocase ascii wide
                        $string9 = /\/smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string10 = /\\quickcrack\.py/ nocase ascii wide
                        $string11 = /\\redirecttosmb\.py/ nocase ascii wide
                        $string12 = /\\smbtrap2\.py/ nocase ascii wide
                        $string13 = /\\smbtrap\-mitmproxy\-inline\.py/ nocase ascii wide
                        $string14 = "06f43329147155af22520cda36202f9af0bd46b5e30b3d3f202d2a463aa2729d" nocase ascii wide
                        $string15 = "432bb0868bd1152ce689dda88d274bb05671174c5c892c7db0575e50abcadf4c" nocase ascii wide
                        $string16 = "c9def37771dabf11171830fdd27b3b751955f40c577fae3f9691188ed3f90b08" nocase ascii wide
                        $string17 = "cylance/SMBTrap" nocase ascii wide
                        $string18 = "de25283c258cc462a919df98ff3033b6f433cf0ab4d92e95a650099839c45e63" nocase ascii wide
                        $string19 = "import try_to_crack_hash" nocase ascii wide
                        $string20 = /redirecttosmb\.py\s/ nocase ascii wide
                        $string21 = "smbtrap-mitmproxy-inline" nocase ascii wide
                        $string22 = /try_to_crack_hash\(/ nocase ascii wide

    condition:
        any of them
}