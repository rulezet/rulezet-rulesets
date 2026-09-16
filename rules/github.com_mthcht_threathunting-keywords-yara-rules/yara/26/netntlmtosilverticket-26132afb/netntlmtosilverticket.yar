rule NetNTLMtoSilverTicket
{
    meta:
        description = "Detection patterns for the tool 'NetNTLMtoSilverTicket' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetNTLMtoSilverTicket"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdementor\.py/ nocase ascii wide
                        $string2 = /\sGet\-SpoolStatus\.ps1/ nocase ascii wide
                        $string3 = /\srpcdump\.py/ nocase ascii wide
                        $string4 = /\.\/hashcat\s\-/
                        $string5 = /\/dementor\.py/ nocase ascii wide
                        $string6 = "/NetNTLMtoSilverTicket" nocase ascii wide
                        $string7 = /\/rpcdump\.py/ nocase ascii wide
                        $string8 = /\/ticketer\.py\s\-/
                        $string9 = /\\dementor\.py/ nocase ascii wide
                        $string10 = /\\Get\-SpoolStatus\.ps1/ nocase ascii wide
                        $string11 = /\\rpcdump\.py/ nocase ascii wide
                        $string12 = "a8421a872b4c4eccc02a0ebb623f9ecc2991e949e4134fc184ca1822da0e5c4c" nocase ascii wide
                        $string13 = "dementor - rough PoC to connect to spoolss to elicit machine account authentication " nocase ascii wide
                        $string14 = /dementor\.py\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string15 = /Got\sexpected\sRPC_S_SERVER_UNAVAILABLE\sexception\.\sAttack\sworked/ nocase ascii wide
                        $string16 = /impacket\.dcerpc\.v5/ nocase ascii wide
                        $string17 = /NetNTLMtoSilverTicket\.git/ nocase ascii wide
                        $string18 = "NetNTLMtoSilverTicket-master" nocase ascii wide
                        $string19 = /ntlmv1\.py\s\-\-ntlmv1\s.{0,1000}\:\:/ nocase ascii wide
                        $string20 = /python3\sntlmv1\.py\s/ nocase ascii wide
                        $string21 = /Responder\.py\s\-I\s/ nocase ascii wide
                        $string22 = /rpcdump\.py\s.{0,1000}\s\|\sgrep\sMS\-RPRN/ nocase ascii wide
                        $string23 = /SpoolSample\.exe\s.{0,1000}\s/ nocase ascii wide
                        $string24 = /ticketer\.py\s\-nthash\s/ nocase ascii wide

    condition:
        any of them
}