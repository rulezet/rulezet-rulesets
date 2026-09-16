rule CMLoot
{
    meta:
        description = "Detection patterns for the tool 'CMLoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CMLoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCMLoot\.ps1/ nocase ascii wide
                        $string2 = /\s\-SCCMHost\s.{0,1000}\s\-Outfile\s/ nocase ascii wide
                        $string3 = /\/CMLoot\.git/ nocase ascii wide
                        $string4 = /\/CMLoot\.ps1/ nocase ascii wide
                        $string5 = /\\CMLoot\.ps1/ nocase ascii wide
                        $string6 = "1njected/CMLoot" nocase ascii wide
                        $string7 = /CMLoot\.psm1/ nocase ascii wide
                        $string8 = "CMLoot-main" nocase ascii wide
                        $string9 = "Invoke-CMLootDownload" nocase ascii wide
                        $string10 = "Invoke-CMLootExtract" nocase ascii wide
                        $string11 = "Invoke-CMLootHunt " nocase ascii wide
                        $string12 = "Invoke-CMLootInventory" nocase ascii wide
                        $string13 = /src\\CMLootOut\\/ nocase ascii wide

    condition:
        any of them
}