rule rule_PowerBreach_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerBreach' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBreach"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerBreach_offensive_tool_keyword = /\sPowerBreach\.ps1/ nocase ascii wide
                        $string2_PowerBreach_offensive_tool_keyword = "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!" nocase ascii wide
                        $string3_PowerBreach_offensive_tool_keyword = /\/PowerBreach\.ps1/ nocase ascii wide
                        $string4_PowerBreach_offensive_tool_keyword = /\\PowerBreach\.ps1/ nocase ascii wide
                        $string5_PowerBreach_offensive_tool_keyword = "4808ad1202bb14375f19929cb389433ffca4b27eaba4490da262a48f57b5af64" nocase ascii wide
                        $string6_PowerBreach_offensive_tool_keyword = "6ce500821488255bc70acd310d8162308fd14a4fa214c79c2d9a354c705de6d7" nocase ascii wide
                        $string7_PowerBreach_offensive_tool_keyword = "Add-PSFirewallRules" nocase ascii wide
                        $string8_PowerBreach_offensive_tool_keyword = "Invoke-CallbackIEX" nocase ascii wide
                        $string9_PowerBreach_offensive_tool_keyword = "Invoke-DeadUserBackdoor" nocase ascii wide
                        $string10_PowerBreach_offensive_tool_keyword = "Invoke-EventLogBackdoor" nocase ascii wide
                        $string11_PowerBreach_offensive_tool_keyword = "Invoke-LoopBackdoor" nocase ascii wide
                        $string12_PowerBreach_offensive_tool_keyword = "Invoke-PortBindBackdoor" nocase ascii wide
                        $string13_PowerBreach_offensive_tool_keyword = "Invoke-PortKnockBackdoor" nocase ascii wide
                        $string14_PowerBreach_offensive_tool_keyword = "Invoke-ResolverBackdoor" nocase ascii wide
                        $string15_PowerBreach_offensive_tool_keyword = /This\sbackdoor\srequires\sAdmin\s\:\(/ nocase ascii wide

    condition:
        any of them
}