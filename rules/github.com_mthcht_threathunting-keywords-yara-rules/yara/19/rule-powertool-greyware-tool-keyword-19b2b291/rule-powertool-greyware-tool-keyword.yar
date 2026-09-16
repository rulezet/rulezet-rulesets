rule rule_Powertool_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Powertool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powertool"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Powertool_greyware_tool_keyword = /\[PowerTool\]\sname\=\%s\,\ssize\=\%d\,\s\%d/ nocase ascii wide
                        $string2_Powertool_greyware_tool_keyword = /\\PowerTool\.exe/ nocase ascii wide
                        $string3_Powertool_greyware_tool_keyword = /\\PowerTool\.pdb/ nocase ascii wide
                        $string4_Powertool_greyware_tool_keyword = /\\PowerTool32\.exe/ nocase ascii wide
                        $string5_Powertool_greyware_tool_keyword = /\\PowerTool64\.exe/ nocase ascii wide
                        $string6_Powertool_greyware_tool_keyword = "094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde" nocase ascii wide
                        $string7_Powertool_greyware_tool_keyword = "611db45c564ffb1b67a85b2249f30e5a95f2b7ab2ceec403cb22555a708c61d9" nocase ascii wide
                        $string8_Powertool_greyware_tool_keyword = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string9_Powertool_greyware_tool_keyword = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string10_Powertool_greyware_tool_keyword = "d321ce59062c8d96dacdfe13e84d1543a296c432291dd4488d79f6b94a565923" nocase ascii wide
                        $string11_Powertool_greyware_tool_keyword = "Detection may be stuck, First confirm whether the device hijack in " nocase ascii wide
                        $string12_Powertool_greyware_tool_keyword = /d\-h\.st\/users\/powertool/ nocase ascii wide
                        $string13_Powertool_greyware_tool_keyword = /whether\sto\sdownload\sthe\s64bit\sversion\sof\sPowerTool\?/ nocase ascii wide

    condition:
        any of them
}