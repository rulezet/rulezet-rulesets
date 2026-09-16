rule Powertool
{
    meta:
        description = "Detection patterns for the tool 'Powertool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powertool"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\[PowerTool\]\sname\=\%s\,\ssize\=\%d\,\s\%d/ nocase ascii wide
                        $string2 = /\\PowerTool\.exe/ nocase ascii wide
                        $string3 = /\\PowerTool\.pdb/ nocase ascii wide
                        $string4 = /\\PowerTool32\.exe/ nocase ascii wide
                        $string5 = /\\PowerTool64\.exe/ nocase ascii wide
                        $string6 = "094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde" nocase ascii wide
                        $string7 = "611db45c564ffb1b67a85b2249f30e5a95f2b7ab2ceec403cb22555a708c61d9" nocase ascii wide
                        $string8 = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string9 = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string10 = "d321ce59062c8d96dacdfe13e84d1543a296c432291dd4488d79f6b94a565923" nocase ascii wide
                        $string11 = "Detection may be stuck, First confirm whether the device hijack in " nocase ascii wide
                        $string12 = /d\-h\.st\/users\/powertool/ nocase ascii wide
                        $string13 = /whether\sto\sdownload\sthe\s64bit\sversion\sof\sPowerTool\?/ nocase ascii wide

    condition:
        any of them
}