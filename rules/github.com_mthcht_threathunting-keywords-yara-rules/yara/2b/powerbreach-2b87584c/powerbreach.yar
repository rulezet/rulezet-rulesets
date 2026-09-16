rule PowerBreach
{
    meta:
        description = "Detection patterns for the tool 'PowerBreach' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBreach"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPowerBreach\.ps1/ nocase ascii wide
                        $string2 = "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!" nocase ascii wide
                        $string3 = /\/PowerBreach\.ps1/ nocase ascii wide
                        $string4 = /\\PowerBreach\.ps1/ nocase ascii wide
                        $string5 = "4808ad1202bb14375f19929cb389433ffca4b27eaba4490da262a48f57b5af64" nocase ascii wide
                        $string6 = "6ce500821488255bc70acd310d8162308fd14a4fa214c79c2d9a354c705de6d7" nocase ascii wide
                        $string7 = "Add-PSFirewallRules" nocase ascii wide
                        $string8 = "Invoke-CallbackIEX" nocase ascii wide
                        $string9 = "Invoke-DeadUserBackdoor" nocase ascii wide
                        $string10 = "Invoke-EventLogBackdoor" nocase ascii wide
                        $string11 = "Invoke-LoopBackdoor" nocase ascii wide
                        $string12 = "Invoke-PortBindBackdoor" nocase ascii wide
                        $string13 = "Invoke-PortKnockBackdoor" nocase ascii wide
                        $string14 = "Invoke-ResolverBackdoor" nocase ascii wide
                        $string15 = /This\sbackdoor\srequires\sAdmin\s\:\(/ nocase ascii wide

    condition:
        any of them
}