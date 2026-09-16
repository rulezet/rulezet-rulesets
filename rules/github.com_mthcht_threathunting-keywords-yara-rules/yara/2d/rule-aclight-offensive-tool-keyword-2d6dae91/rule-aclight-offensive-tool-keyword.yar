rule rule_ACLight_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ACLight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACLight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ACLight_offensive_tool_keyword = /\s\-\sSensitive\sAccounts\.csv/ nocase ascii wide
                        $string2_ACLight_offensive_tool_keyword = /\/ACLight\.git/ nocase ascii wide
                        $string3_ACLight_offensive_tool_keyword = "/ACLight/" nocase ascii wide
                        $string4_ACLight_offensive_tool_keyword = /\\scanACLsResults\.csv/ nocase ascii wide
                        $string5_ACLight_offensive_tool_keyword = /Accounts\swith\sextra\spermissions\.txt/ nocase ascii wide
                        $string6_ACLight_offensive_tool_keyword = /ACLight\.ps1/ nocase ascii wide
                        $string7_ACLight_offensive_tool_keyword = /ACLight\.psd1/ nocase ascii wide
                        $string8_ACLight_offensive_tool_keyword = /ACLight\.psm1/ nocase ascii wide
                        $string9_ACLight_offensive_tool_keyword = /ACLight2\.ps1/ nocase ascii wide
                        $string10_ACLight_offensive_tool_keyword = /ACLight2\.psd1/ nocase ascii wide
                        $string11_ACLight_offensive_tool_keyword = /ACLight2\.psm1/ nocase ascii wide
                        $string12_ACLight_offensive_tool_keyword = "ACLight-master" nocase ascii wide
                        $string13_ACLight_offensive_tool_keyword = "cyberark/ACLight" nocase ascii wide
                        $string14_ACLight_offensive_tool_keyword = /Execute\-ACLight\.bat/ nocase ascii wide
                        $string15_ACLight_offensive_tool_keyword = /Execute\-ACLight2\.bat/ nocase ascii wide
                        $string16_ACLight_offensive_tool_keyword = "Invoke-ACLcsvFileAnalysis" nocase ascii wide
                        $string17_ACLight_offensive_tool_keyword = /Invoke\-ACLScanner\s.{0,1000}\s\-Filter\s/ nocase ascii wide
                        $string18_ACLight_offensive_tool_keyword = /Invoke\-ACLScanner\s.{0,1000}\s\-Name\s/ nocase ascii wide
                        $string19_ACLight_offensive_tool_keyword = /Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt/ nocase ascii wide
                        $string20_ACLight_offensive_tool_keyword = /Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv/ nocase ascii wide
                        $string21_ACLight_offensive_tool_keyword = /Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv/ nocase ascii wide
                        $string22_ACLight_offensive_tool_keyword = "Start-ACLsAnalysis -Domain" nocase ascii wide
                        $string23_ACLight_offensive_tool_keyword = "Start-domainACLsAnalysis" nocase ascii wide
                        $string24_ACLight_offensive_tool_keyword = "starting Multi-Layered ACLight scan" nocase ascii wide

    condition:
        any of them
}