rule ACLight
{
    meta:
        description = "Detection patterns for the tool 'ACLight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACLight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\sSensitive\sAccounts\.csv/ nocase ascii wide
                        $string2 = /\/ACLight\.git/ nocase ascii wide
                        $string3 = "/ACLight/" nocase ascii wide
                        $string4 = /\\scanACLsResults\.csv/ nocase ascii wide
                        $string5 = /Accounts\swith\sextra\spermissions\.txt/ nocase ascii wide
                        $string6 = /ACLight\.ps1/ nocase ascii wide
                        $string7 = /ACLight\.psd1/ nocase ascii wide
                        $string8 = /ACLight\.psm1/ nocase ascii wide
                        $string9 = /ACLight2\.ps1/ nocase ascii wide
                        $string10 = /ACLight2\.psd1/ nocase ascii wide
                        $string11 = /ACLight2\.psm1/ nocase ascii wide
                        $string12 = "ACLight-master" nocase ascii wide
                        $string13 = "cyberark/ACLight" nocase ascii wide
                        $string14 = /Execute\-ACLight\.bat/ nocase ascii wide
                        $string15 = /Execute\-ACLight2\.bat/ nocase ascii wide
                        $string16 = "Invoke-ACLcsvFileAnalysis" nocase ascii wide
                        $string17 = /Invoke\-ACLScanner\s.{0,1000}\s\-Filter\s/ nocase ascii wide
                        $string18 = /Invoke\-ACLScanner\s.{0,1000}\s\-Name\s/ nocase ascii wide
                        $string19 = /Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt/ nocase ascii wide
                        $string20 = /Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv/ nocase ascii wide
                        $string21 = /Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv/ nocase ascii wide
                        $string22 = "Start-ACLsAnalysis -Domain" nocase ascii wide
                        $string23 = "Start-domainACLsAnalysis" nocase ascii wide
                        $string24 = "starting Multi-Layered ACLight scan" nocase ascii wide

    condition:
        any of them
}